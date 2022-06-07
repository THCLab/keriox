use std::{convert::TryFrom, path::Path, sync::Arc};

use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::{SerializationFormats},
    event_message::{
        signed_event_message::{Message},
    },
    event_parsing::message::signed_event_stream,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::{
        basic_processor::BasicProcessor,
    },
    query::{
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer, state::IdentifierState,
};

use keri::component::Component;

pub struct Watcher {
    pub prefix: BasicPrefix,
    pub component: Component<BasicProcessor>,
    pub signer: Arc<Signer>,
}

impl Watcher {
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

    pub fn get_state_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
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
