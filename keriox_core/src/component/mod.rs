use std::{convert::TryFrom, path::Path, sync::Arc};

use crate::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::receipt::Receipt,
    event_message::{
        event_msg_builder::ReceiptBuilder,
        key_event_message::KeyEvent,
        serialization_info::SerializationFormats,
        signed_event_message::{Message, SignedNontransferableReceipt},
        EventMessage,
    },
    event_parsing::message::signed_event_stream,
    oobi::{LocationScheme, OobiManager, Role},
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::{
        event_processor::Processor,
        event_storage::EventStorage,
        notification::Notification,
        responder::Responder,
    },
    query::{
        key_state_notice::KeyStateNotice,
        query_event::{QueryData, SignedQuery},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
};

pub struct NontransferableActor<P: Processor> {
    pub prefix: BasicPrefix,
    pub actor: Actor<P>,
    pub signer: Arc<Signer>,
    pub oobi_manager: Arc<OobiManager>,
    responder: Arc<Responder<Notification>>,
}

impl<P: Processor> NontransferableActor<P> {
    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let signer = priv_key
            .map(|key| Signer::new_with_seed(&key.parse()?))
            .unwrap_or(Ok(Signer::new()))?;
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let witness = Actor::<P>::new(event_db_path)?;
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
        oobi_manager.save_oobi(signed_reply)?;
        let responder = Arc::new(Responder::new());
        Ok(Self {
            prefix,
            actor: witness,
            oobi_manager,
            signer: Arc::new(signer),
            responder,
        })
    }

    pub fn respond(&self, signer: Arc<Signer>) -> Result<Vec<Message>, Error> {
        let response = Vec::new();
        while let Some(event) = self.responder.get_data_to_respond() {
            match event {
                Notification::KeyEventAdded(event) => {
                    let non_trans_receipt =
                        self.respond_to_key_event(event.event_message, signer.clone())?;
                    self.actor.storage.add_mailbox_receipt(non_trans_receipt)?;
                }
                _ => return Err(Error::SemanticError("Wrong notification type".into())),
            }
        }
        Ok(response)
    }

    fn respond_to_key_event(
        &self,
        event_message: EventMessage<KeyEvent>,
        signer: Arc<Signer>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = signer.sign(&ser)?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message)
            .build()?;

        let signature = SelfSigning::Ed25519Sha512.derive(signature);

        let signed_rcp = SignedNontransferableReceipt::new(
            &rcp,
            Some(vec![(self.prefix.clone(), signature)]),
            None,
        );

        self.actor
            .processor
            .process(Message::NontransferableRct(signed_rcp.clone()))?;
        Ok(signed_rcp)
    }

    pub fn get_signed_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let ksn = self.actor.get_ksn_for_prefix(prefix)?;
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

    pub fn get_end_role_for_id(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(self.oobi_manager.get_end_role(cid, role).unwrap())
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(match self.oobi_manager.get_loc_scheme(eid).unwrap() {
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

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: Message) -> Result<Vec<Message>, Error> {
        let mut responses = Vec::new();
        match msg.clone() {
            Message::Event(ev) => {
                self.actor.process(&msg).unwrap();
                // check if receipts are attached
                if let Some(witness_receipts) = ev.witness_receipts {
                    // Create and process witness receipts
                    // TODO What timestamp should be set?
                    let id = ev.event_message.event.get_prefix();
                    let receipt = Receipt {
                        receipted_event_digest: ev.event_message.get_digest(),
                        prefix: id,
                        sn: ev.event_message.event.get_sn(),
                    };
                    let signed_receipt = SignedNontransferableReceipt::new(
                        &receipt.to_message(SerializationFormats::JSON).unwrap(),
                        None,
                        Some(witness_receipts),
                    );
                    self.actor
                        .process(&Message::NontransferableRct(signed_receipt))
                        .unwrap();
                }
            }
            Message::Query(qry) => {
                let response = self
                    .actor
                    .process_signed_query(qry)
                    .unwrap();
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
                    ReplyType::Kel(msgs) | ReplyType::Mbx(msgs)  => responses.extend(msgs),
                };
            }
            Message::NontransferableRct(_) => self.actor.process(&msg).unwrap(),
            Message::TransferableRct(_) => self.actor.process(&msg).unwrap(),
            Message::Reply(reply) => match reply.reply.get_route() {
                ReplyRoute::Ksn(_, _) => self.actor.process(&msg).unwrap(),
                ReplyRoute::LocScheme(_)
                | ReplyRoute::EndRoleAdd(_)
                | ReplyRoute::EndRoleCut(_) => self.oobi_manager.process_oobi(reply).unwrap(),
            },
        };
        Ok(responses)
    }

    pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<(), Error> {
        let (_, msgs) = signed_event_stream(input_stream)
            .map_err(|e| Error::DeserializeError(e.to_string()))
            .unwrap();

        for msg in msgs {
            let msg = Message::try_from(msg).unwrap();
            self.process(msg)?;
        }
        Ok(())
    }
}

pub struct Actor<P: Processor> {
    processor: P,
    pub storage: EventStorage,
}

impl<P: Processor> Actor<P> {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let (processor, storage) = {
            let witness_db = Arc::new(SledEventDatabase::new(path)?);
            (
                P::new(witness_db.clone()),
                EventStorage::new(witness_db.clone()),
            )
        };

        Ok(Self {
            processor,
            storage,
        })
    }

    pub fn get_db_ref(&self) -> Arc<SledEventDatabase> {
        self.storage.db.clone()
    }

    pub fn process(&self, msg: &Message) -> Result<(), Error> {
        self.processor.process(msg.clone())
    }

    pub fn get_kel_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_kel(id)
    }

    pub fn get_receipts_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_escrowed_nt_receipts(id)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_ksn_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<KeyStateNotice, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
        Ok(ksn)
    }

    pub fn process_signed_query(
        &self,
        qr: SignedQuery,
    ) -> Result<ReplyType, Error> {
        let signatures = qr.signatures;
        // check signatures
        let kc = self
            .storage
            .get_state(&qr.signer)?
            .ok_or_else(|| Error::SemanticError("No signer identifier in db".into()))?
            .current;

        if kc.verify(&qr.query.serialize()?, &signatures)? {
            // TODO check timestamps
            // unpack and check what's inside
            self.process_query(qr.query.get_query_data())
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    fn process_query(&self, qr: QueryData) -> Result<ReplyType, Error> {
        use crate::query::query_event::QueryRoute;

        match qr.route {
            QueryRoute::Log { args, .. } => Ok(ReplyType::Kel(
                self.storage
                    .get_kel_messages_with_receipts(&args.i)?
                    .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?,
            )),
            QueryRoute::Ksn { args, .. } => {
                let i = args.i;
                // return reply message with ksn inside
                let state = self
                    .storage
                    .get_state(&i)?
                    .ok_or_else(|| Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                Ok(ReplyType::Ksn(ksn))
            }
            QueryRoute::Mbx { args, .. } => {
                let mail = self.storage.get_mailbox_events(args)?;
                Ok(ReplyType::Mbx(mail))
            }
        }
    }
}

#[test]
pub fn test_ksn_query() -> Result<(), Error> {
    use std::convert::TryFrom;

    use crate::event_parsing::message::signed_message;
    use crate::processor::witness_processor::WitnessProcessor;
    use tempfile::Builder;
    use url;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let oobi_root = Builder::new().prefix("test-db2").tempdir().unwrap();

    let witness = NontransferableActor::<WitnessProcessor>::setup(
        url::Url::parse("http://localhost").unwrap(),
        root.path(),
        oobi_root.path(),
        None,
    )?;
    // Process inception event and its receipts. To accept inception event it must be fully witnessed.
    let rcps = r#"{"v":"KERI10JSON000091_","t":"rct","d":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","s":"0"}-BADAAI_M_762PE-i9uhbB_Ynxsx4mfvCA73OHM96U8SQtsgV0co4kGuSw0tMtiQWBYwA9bvDZ7g-ZfhFLtXJPorbtDwABDsQTBpHVpNI-orK8606K5oUSr5sv5LYvyuEHW3dymwVIDRYWUVxMITMp_st7Ee4PjD9nIQCzAeXHDcZ6c14jBQACPySjFKPkqeu5eiB0YfcYLQpvo0vnu6WEQ4XJnzNWWrV9JuOQ2AfWVeIc0D7fuK4ofXMRhTxAXm-btkqTrm0tBA"#;

    let icp_str = r#"{"v":"KERI10JSON0001b7_","t":"icp","d":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","s":"0","kt":"1","k":["DWow4n8Wxqf_UTvzoSnWOrxELM3ptd-mbtZC146khE4w"],"nt":"1","n":["EcjtYj92jg7qK_T1-5bWUlnBU6bdVWP-yMxBHjr_Quo8"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-AABAA0Dn5vYNWAz8uN1N9cCR-HfBQhDIhb-Crt_1unJY7KTAfz0iwa9FPWHFLTgvTkd0yUSw3AZuNc5Xbr-VMzQDhBw"#;
    let to_process: Vec<_> = [icp_str, rcps]
        .iter()
        .map(|event| {
            let parsed = signed_message(event.as_bytes()).unwrap().1;
            Message::try_from(parsed).unwrap()
        })
        .collect();
    for msg in to_process {
        witness.process(msg).unwrap();
    }

    let qry_str = r#"{"v":"KERI10JSON000104_","t":"qry","d":"ErXRrwRbUFylKDiuOp8a1wO2XPAY4KiMX4TzYWZ1iAGE","dt":"2022-03-21T11:42:58.123955+00:00","r":"ksn","rr":"","q":{"s":0,"i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}-VAj-HABE6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM-AABAAk-Hyv8gpUZNpPYDGJc5F5vrLNWlGM26523Sgb6tKN1CtP4QxUjEApJCRxfm9TN8oW2nQ40QVM_IuZlrly1eLBA"#;

    let parsed = signed_message(qry_str.as_bytes()).unwrap().1;
    let deserialized_qry = Message::try_from(parsed).unwrap();

    let r = witness.process(deserialized_qry)?;
    // should respond with reply message
    assert_eq!(r.len(), 1);

    match &r[0] {
        Message::Reply(signed_reply) => {
            if let ReplyRoute::Ksn(id, ksn) = &signed_reply.reply.event.content.data {
                assert_eq!(id, &IdentifierPrefix::Basic(witness.prefix));
                assert_eq!(
                    ksn.state.prefix,
                    "E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM"
                        .parse()
                        .unwrap()
                );
                assert_eq!(ksn.state.sn, 0);
            }
        }
        _ => panic!("Wrong event type"),
    };

    Ok(())
}
