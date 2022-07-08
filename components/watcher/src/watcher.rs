use std::{path::Path, sync::Arc};

use derive_more::{Display, Error, From};
use keri::{
    actor::{parse_notice_stream, parse_op_stream, prelude::*},
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event_message::signed_event_message::{Notice, Op},
    oobi::{error::OobiError, EndRole, LocationScheme, OobiManager, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix},
    query::{
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
};

pub struct WatcherData {
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor,
    event_storage: EventStorage,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
}

impl WatcherData {
    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or(Ok(Signer::new()))?,
        );
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let db = Arc::new(SledEventDatabase::new(event_db_path)?);
        let processor = BasicProcessor::new(db.clone());
        let storage = EventStorage::new(db.clone());
        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(prefix.clone()),
            public_address.scheme().parse().unwrap(),
            public_address.clone(),
        );
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            prefix.clone(),
            SelfSigning::Ed25519Sha512.derive(signer.sign(reply.serialize()?)?),
        );
        let oobi_manager = OobiManager::new(oobi_db_path);
        oobi_manager.save_oobi(&signed_reply)?;
        Ok(Self {
            prefix,
            processor,
            event_storage: storage,
            signer: signer,
            oobi_manager,
        })
    }

    /// Get location scheme from OOBI manager and sign it.
    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Vec<SignedReply>, WatcherError> {
        Ok(match self.oobi_manager.get_loc_scheme(eid)? {
            Some(oobis_to_sign) => oobis_to_sign
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.serialize().unwrap())?;
                    Ok(SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.prefix.clone(),
                        SelfSigning::Ed25519Sha512.derive(signature),
                    ))
                })
                .collect::<Result<_, Error>>()?,
            None => return Err(WatcherError::NoLocation { id: eid.clone() }),
        })
    }

    pub fn get_signed_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let ksn = self
            .event_storage
            .get_ksn_for_prefix(prefix, SerializationFormats::JSON)?;
        let rpy = ReplyEvent::new_reply(
            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;

        let signature = SelfSigning::Ed25519Sha512.derive(signer.sign(&rpy.serialize()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn get_state_for_prefix(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.event_storage.get_state(id)
    }

    fn process_notice(&self, notice: Notice) -> Result<(), Error> {
        process_notice(notice, &self.processor)
    }

    fn process_op(&self, op: Op) -> Result<Vec<Message>, Error> {
        let mut responses = Vec::new();
        match op {
            Op::Query(qry) => {
                let response = process_signed_query(qry, &self.event_storage).unwrap();
                match response {
                    ReplyType::Ksn(ksn) => {
                        let rpy = ReplyEvent::new_reply(
                            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                            SelfAddressing::Blake3_256,
                            SerializationFormats::JSON,
                        )?;

                        let signature =
                            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
                        let reply = Message::Op(Op::Reply(SignedReply::new_nontrans(
                            rpy,
                            self.prefix.clone(),
                            signature,
                        )));
                        responses.push(reply);
                    }
                    ReplyType::Kel(msgs) | ReplyType::Mbx(msgs) => responses.extend(msgs),
                };
            }
            Op::Reply(reply) => {
                process_reply(
                    reply,
                    &self.oobi_manager,
                    &self.processor,
                    &self.event_storage,
                )?;
            }
        }
        Ok(responses)
    }

    pub fn parse_and_process_notices(&self, input_stream: &[u8]) -> Result<(), Error> {
        parse_notice_stream(input_stream)?
            .into_iter()
            .map(|notice| self.process_notice(notice))
            .collect()
    }

    pub fn parse_and_process_ops(&self, input_stream: &[u8]) -> Result<Vec<Message>, Error> {
        parse_op_stream(input_stream)?
            .into_iter()
            .flat_map(|op| match self.process_op(op) {
                Ok(msgs) => msgs.into_iter().map(Ok).collect(),
                Err(e) => vec![Err(e)],
            })
            .collect()
    }
}

pub struct Watcher(pub WatcherData);

impl Watcher {
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<(), WatcherError> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .0
            .get_loc_scheme_for_id(&er.eid.clone())?
            .get(0)
            .ok_or(WatcherError::NoLocation { id: er.eid.clone() })?
            .reply
            .event
            .content
            .data
            .clone();

        if let ReplyRoute::LocScheme(lc) = loc_scheme {
            let url = format!("{}oobi/{}/{}/{}", lc.url, er.cid, "witness", er.eid);
            let oobis = reqwest::get(url).await.unwrap().text().await?;

            self.0.parse_and_process_ops(oobis.as_bytes())?;
            Ok(())
        } else {
            Err(OobiError::InvalidMessageType)?
        }
    }

    pub async fn resolve_loc_scheme(&self, lc: &LocationScheme) -> Result<(), WatcherError> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await?.text().await?;

        self.0.parse_and_process_ops(oobis.as_bytes())?;

        Ok(())
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>, WatcherError> {
        self.0
            .get_loc_scheme_for_id(id)?
            .iter()
            .map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.reply.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(WatcherError::WrongReplyRoute)
                }
            })
            .collect()
    }

    pub async fn send_to(
        &self,
        wit_id: IdentifierPrefix,
        scheme: Scheme,
        msg: Vec<u8>,
    ) -> Result<Option<String>, WatcherError> {
        let addresses = self.get_loc_schemas(&wit_id)?;
        match addresses
            .iter()
            .find(|loc| loc.scheme == scheme)
            .map(|lc| &lc.url)
        {
            Some(address) => match scheme {
                Scheme::Http => {
                    let client = reqwest::Client::new();
                    let response = client
                        .post(format!("{}process", address))
                        .body(msg)
                        .send()
                        .await?
                        .text()
                        .await?;

                    println!("\ngot response: {}", response);
                    Ok(Some(response))
                }
                Scheme::Tcp => {
                    todo!()
                }
            },
            _ => Err(WatcherError::UnsupportedScheme { id: wit_id, scheme })?,
        }
    }
}

#[derive(Debug, Display, Error, From)]
pub enum WatcherError {
    #[display(fmt = "HTTP request failed")]
    #[from]
    RequestFailed(reqwest::Error),

    #[display(fmt = "keri error")]
    #[from]
    KeriError(keri::error::Error),

    #[display(fmt = "DB error")]
    #[from]
    DbError(keri::database::sled::DbError),

    #[display(fmt = "OOBI error")]
    #[from]
    OobiError(keri::oobi::error::OobiError),

    #[display(fmt = "location not found for {id:?}")]
    NoLocation { id: IdentifierPrefix },

    #[display(fmt = "unsupported scheme {scheme:?} for {id:?}")]
    UnsupportedScheme {
        id: IdentifierPrefix,
        scheme: Scheme,
    },

    #[display(fmt = "wrong reply route")]
    WrongReplyRoute,
}
