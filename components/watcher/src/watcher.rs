use anyhow::{anyhow, Result};
use std::{convert::TryFrom, path::Path, sync::Arc};

use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    event_message::signed_event_message::Message,
    event_parsing::message::signed_event_stream,
    oobi::{EndRole, LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::basic_processor::BasicProcessor,
    query::{
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
};

use keri::component::Component;

pub struct WatcherData {
    pub prefix: BasicPrefix,
    pub component: Component<BasicProcessor>,
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
        let watcher = Component::<BasicProcessor>::new(db.clone(), oobi_db_path)?;
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
        watcher.oobi_manager.save_oobi(signed_reply)?;
        Ok(Self {
            prefix,
            component: watcher,
            signer: signer,
        })
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(match self.component.get_loc_scheme_for_id(eid)? {
            Some(oobis_to_sign) => Some(
                oobis_to_sign
                    .iter()
                    .map(|oobi_to_sing| {
                        let signature =
                            self.signer.sign(oobi_to_sing.serialize().unwrap()).unwrap();
                        SignedReply::new_nontrans(
                            oobi_to_sing.clone(),
                            self.prefix.clone(),
                            SelfSigning::Ed25519Sha512.derive(signature),
                        )
                    })
                    .collect(),
            ),
            None => None,
        })
    }

    pub fn get_signed_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let ksn = self.component.get_ksn_for_prefix(prefix)?;
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
        self.component.get_state_for_prefix(id)
    }

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: Message) -> Result<Vec<Message>, Error> {
        let mut responses = Vec::new();
        match msg.clone() {
            Message::Query(qry) => {
                let response = self.component.process_signed_query(qry).unwrap();
                match response {
                    ReplyType::Ksn(ksn) => {
                        let rpy = ReplyEvent::new_reply(
                            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                            SelfAddressing::Blake3_256,
                            SerializationFormats::JSON,
                        )?;

                        let signature =
                            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
                        let reply = Message::Reply(SignedReply::new_nontrans(
                            rpy,
                            self.prefix.clone(),
                            signature,
                        ));
                        responses.push(reply);
                    }
                    ReplyType::Kel(msgs) | ReplyType::Mbx(msgs) => responses.extend(msgs),
                };
                Ok(())
            }
            _ => self.component.process(msg),
        }?;
        Ok(responses)
    }

    pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<Vec<Message>, Error> {
        let (_, msgs) = signed_event_stream(input_stream)
            .map_err(|e| Error::DeserializeError(e.to_string()))
            .unwrap();

        let output = msgs
            .into_iter()
            .map(|msg| -> Result<_, _> {
                let msg = Message::try_from(msg)?;
                self.process(msg)
            })
            // TODO: avoid unwrap
            .map(|d| d.unwrap())
            .flatten()
            .collect();
        Ok(output)
    }
}

pub struct Watcher(pub WatcherData);

impl Watcher {
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<()> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .0
            .get_loc_scheme_for_id(&er.eid.clone())
            .unwrap()
            .unwrap()[0]
            .reply
            .event
            .content
            .data
            .clone();

        if let ReplyRoute::LocScheme(lc) = loc_scheme {
            let url = format!("{}oobi/{}/{}/{}", lc.url, er.cid, "witness", er.eid);
            let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();

            self.0.parse_and_process(oobis.as_bytes()).unwrap();
            Ok(())
        } else {
            Err(anyhow!("Wrong oobi type"))
        }
    }

    pub async fn resolve_loc_scheme(&self, lc: &LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();

        self.0.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        Ok(self
            .0
            .get_loc_scheme_for_id(id)
            .unwrap()
            .unwrap()
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.reply.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(anyhow!("Wrong route type"))
                }
                .ok()
            })
            .collect())
    }

    pub async fn send_to(
        &self,
        wit_id: IdentifierPrefix,
        schema: Scheme,
        msg: Vec<u8>,
    ) -> Result<Option<String>> {
        let addresses = self.get_loc_schemas(&wit_id)?;
        match addresses
            .iter()
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => match schema {
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
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }
}
