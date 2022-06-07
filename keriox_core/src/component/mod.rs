use std::{path::Path, sync::Arc};

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::{serialization_info::SerializationFormats, signed_event_message::Message},
    oobi::{OobiManager, Role},
    prefix::IdentifierPrefix,
    processor::{
        event_storage::EventStorage, notification::Notifier, validator::EventValidator, Processor,
    },
    query::{
        key_state_notice::KeyStateNotice,
        query_event::{QueryData, SignedQuery},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    state::IdentifierState,
};

pub struct Component<P: Processor> {
    processor: P,
    pub storage: EventStorage,
    pub oobi_manager: Arc<OobiManager>,
}

impl<P: Processor> Component<P> {
    pub fn new(db: Arc<SledEventDatabase>, oobi_db_path: &Path) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let (processor, storage) = { (P::new(db.clone()), EventStorage::new(db.clone())) };

        Ok(Self {
            processor,
            storage,
            oobi_manager,
        })
    }

    pub fn register_observer(
        &mut self,
        observer: Arc<dyn Notifier + Send + Sync>,
    ) -> Result<(), Error> {
        self.processor.register_observer(observer)
    }

    pub fn save_oobi(&self, signed_oobi: SignedReply) -> Result<(), Error> {
        self.oobi_manager.save_oobi(signed_oobi)
    }

    pub fn get_db_ref(&self) -> Arc<SledEventDatabase> {
        self.storage.db.clone()
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
    ) -> Result<Option<Vec<ReplyEvent>>, Error> {
        Ok(self.oobi_manager.get_loc_scheme(eid)?)
    }

    pub fn get_ksn_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<KeyStateNotice, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
        Ok(ksn)
    }

    /// Process for events that updates database
    pub fn process(&self, msg: Message) -> Result<(), Error> {
        match msg.clone() {
            Message::Reply(sr) => match sr.reply.get_route() {
                ReplyRoute::LocScheme(_)
                | ReplyRoute::EndRoleAdd(_)
                | ReplyRoute::EndRoleCut(_) => {
                    let validator = EventValidator::new(self.get_db_ref());
                    // check signature
                    validator.verify(&sr.reply.serialize()?, &sr.signature)?;
                    // check digest
                    sr.reply.check_digest()?;
                    // save
                    self.oobi_manager.process_oobi(sr)
                }
                ReplyRoute::Ksn(_, _) => self.processor.process(msg),
            },

            _ => self.processor.process(msg),
        }
    }

    pub fn process_signed_query(&self, qr: SignedQuery) -> Result<ReplyType, Error> {
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
    use crate::event_message::signed_event_message::Message;
    use std::convert::TryFrom;

    use crate::event_parsing::message::signed_message;
    use crate::processor::basic_processor::BasicProcessor;
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let oobi_root = Builder::new().prefix("test-db2").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path())?);

    let controller = Component::<BasicProcessor>::new(db, oobi_root.path())?;
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
        controller.process(msg).unwrap();
    }

    let qry_str = r#"{"v":"KERI10JSON000104_","t":"qry","d":"ErXRrwRbUFylKDiuOp8a1wO2XPAY4KiMX4TzYWZ1iAGE","dt":"2022-03-21T11:42:58.123955+00:00","r":"ksn","rr":"","q":{"s":0,"i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}-VAj-HABE6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM-AABAAk-Hyv8gpUZNpPYDGJc5F5vrLNWlGM26523Sgb6tKN1CtP4QxUjEApJCRxfm9TN8oW2nQ40QVM_IuZlrly1eLBA"#;

    let parsed = signed_message(qry_str.as_bytes()).unwrap().1;
    if let Message::Query(signed_query) = Message::try_from(parsed).unwrap() {
        let r = controller.process_signed_query(signed_query)?;

        if let ReplyType::Ksn(ksn) = r {
            assert_eq!(
                ksn.state.prefix,
                "E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM"
                    .parse()
                    .unwrap()
            );
            assert_eq!(ksn.state.sn, 0);
        } else {
            panic!("Wrong reply")
        }
    }

    Ok(())
}

#[cfg(feature = "oobi")]
#[test]
fn processs_oobi() -> Result<(), Error> {
    use std::convert::TryFrom;

    use crate::{
        component::Component, event_parsing::message::signed_event_stream,
        processor::basic_processor::BasicProcessor,
    };
    use tempfile::Builder;

    let oobi_rpy = r#"{"v":"KERI10JSON000116_","t":"rpy","d":"EZuWRhrNl9gNIck0BcLiPegTJTw3Ng_Hq3WTF8BOQ-sk","dt":"2022-04-12T08:27:47.009114+00:00","r":"/end/role/add","a":{"cid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","role":"controller","eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0Bke1uKEan_LNlP3e5huCO7zHEi50L18FB1-DdskAEyuehw9gMjNMhex73C9Yr0WlkP1B1-JjNIKDVm816zCgmCw"#;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let component = Component::<BasicProcessor>::new(db, oobi_root.path())?;
    let events = signed_event_stream(oobi_rpy.as_bytes()).unwrap().1;
    for event in events {
        let event = Message::try_from(event)?;
        let res = component.process(event);
        assert!(res.is_ok())
    }
    Ok(())
}
