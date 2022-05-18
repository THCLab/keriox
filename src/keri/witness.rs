use std::convert::TryFrom;
use std::path::Path;
use std::sync::Arc;

use crate::event::receipt::Receipt;
use crate::event::EventMessage;
use crate::event_message::event_msg_builder::ReceiptBuilder;
use crate::event_message::key_event_message::KeyEvent;
use crate::event_message::signed_event_message::{Message, SignedNontransferableReceipt};
use crate::event_parsing::message::signed_event_stream;
use crate::keys::PublicKey;
use crate::oobi::OobiManager;
use crate::processor::escrow::default_escrow_bus;
use crate::processor::event_storage::EventStorage;
use crate::processor::notification::{JustNotification, Notification, NotificationBus};
use crate::processor::witness_processor::WitnessProcessor;
use crate::query::reply_event::{ReplyEvent, ReplyRoute, SignedReply};
use crate::query::{
    key_state_notice::KeyStateNotice,
    query_event::{QueryData, SignedQuery},
    QueryRoute, ReplyType,
};

use crate::signer::Signer;
use crate::state::IdentifierState;
use crate::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    prefix::{BasicPrefix, IdentifierPrefix},
};

use super::Responder;

pub struct Witness {
    pub prefix: BasicPrefix,
    processor: WitnessProcessor,
    storage: EventStorage,
    publisher: NotificationBus,
    responder: Arc<Responder<Notification>>,
}

impl Witness {
    pub fn new(path: &Path, pk: PublicKey) -> Result<Self, Error> {
        let (processor, storage, mut publisher) = {
            let witness_db = Arc::new(SledEventDatabase::new(path)?);
            (
                WitnessProcessor::new(witness_db.clone()),
                EventStorage::new(witness_db.clone()),
                default_escrow_bus(witness_db),
            )
        };
        let prefix = Basic::Ed25519NT.derive(pk);
        let responder = Arc::new(Responder::new());
        publisher.register_observer(
            responder.clone(),
            vec![
                JustNotification::KeyEventAdded,
                JustNotification::ReplayLog,
                JustNotification::ReplyKsn,
            ],
        );

        Ok(Self {
            prefix,
            processor,
            storage,
            publisher,
            responder,
        })
    }

    pub fn register_oobi_manager(&mut self, oobi_manager: Arc<OobiManager>) {
        self.publisher
            .register_observer(oobi_manager, vec![JustNotification::GotOobi]);
    }

    pub fn get_db_ref(&self) -> Arc<SledEventDatabase> {
        self.storage.db.clone()
    }

    pub fn respond(&self, signer: Arc<Signer>) -> Result<Vec<Message>, Error> {
        let mut response = Vec::new();
        while let Some(event) = self.responder.get_data_to_respond() {
            match event {
                Notification::KeyEventAdded(event) => {
                    let non_trans_receipt =
                        self.respond_to_key_event(event.event_message, signer.clone())?;
                    response.push(Message::NontransferableRct(non_trans_receipt))
                }
                Notification::ReplayLog(id) => {
                    let mut kel = self
                        .storage
                        .get_kel_messages_with_receipts(&id)
                        .unwrap()
                        .unwrap();
                    response.append(&mut kel)
                }
                Notification::ReplyKsn(signed_reply) => response.push(Message::Reply(signed_reply)),
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

        self.processor
            .process(Message::NontransferableRct(signed_rcp.clone()))?;
        Ok(signed_rcp)
    }

    pub fn parse_and_process(&self, msg: &[u8]) -> Result<(), Error> {
        let events = signed_event_stream(msg)
            .map_err(|e| Error::DeserializeError(e.to_string()))?
            .1
            .into_iter()
            .map(|data| Message::try_from(data));
        events.clone().try_for_each(|msg| {
            let msg = msg?;
            self.process(&vec![msg.clone()])?;
            // check if receipts are attached
            match msg {
                Message::Event(ev) => {
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
                            &receipt.to_message(SerializationFormats::JSON)?,
                            None,
                            Some(witness_receipts),
                        );
                        self.process(&vec![Message::NontransferableRct(signed_receipt)])
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            }
        })
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), Error> {
        let (process_ok, process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                self.processor
                    .process(message.clone())
                    .and_then(|not| self.publisher.notify(&not))
            })
            .partition(Result::is_ok);
        let _oks = process_ok
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        let _errs = process_failed
            .into_iter()
            .map(Result::unwrap_err)
            .collect::<Vec<_>>();

        Ok(())
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

    pub fn get_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
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

    pub fn process_signed_query(
        &self,
        qr: SignedQuery,
        signer: Arc<Signer>,
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
            let route = qr.query.get_route();
            self.process_query(route, qr.query.get_query_data(), signer)
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    #[cfg(feature = "query")]
    fn process_query(
        &self,
        route: QueryRoute,
        qr: QueryData,
        signer: Arc<Signer>,
    ) -> Result<ReplyType, Error> {
        match route {
            QueryRoute::Log => Ok(ReplyType::Kel(
                self.storage
                    .get_kel_messages_with_receipts(&qr.data.i)?
                    .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?,
            )),
            QueryRoute::Ksn => {
                let i = qr.data.i;
                // return reply message with ksn inside
                let state = self
                    .storage
                    .get_state(&i)?
                    .ok_or_else(|| Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;
                let signature = signer.sign(&rpy.serialize()?)?;
                let rpy = SignedReply::new_nontrans(
                    rpy,
                    self.prefix.clone(),
                    SelfSigning::Ed25519Sha512.derive(signature),
                );
                Ok(ReplyType::Rep(rpy))
            }
        }
    }
}

#[cfg(feature = "query")]
#[test]
pub fn test_query() -> Result<(), Error> {
    use std::convert::TryFrom;

    use crate::event_parsing::message::signed_message;
    use crate::keri::witness::Witness;
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let signer_arc = Arc::new(Signer::new());
    let witness = Witness::new(root.path(), signer_arc.clone().public_key())?;
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
    witness.process(to_process.as_slice()).unwrap();
    let response = witness.respond(signer_arc.clone())?;
    // should respond with one receipt event
    assert_eq!(response.len(), 1);

    let qry_str = r#"{"v":"KERI10JSON000104_","t":"qry","d":"ErXRrwRbUFylKDiuOp8a1wO2XPAY4KiMX4TzYWZ1iAGE","dt":"2022-03-21T11:42:58.123955+00:00","r":"ksn","rr":"","q":{"s":0,"i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}-VAj-HABE6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM-AABAAk-Hyv8gpUZNpPYDGJc5F5vrLNWlGM26523Sgb6tKN1CtP4QxUjEApJCRxfm9TN8oW2nQ40QVM_IuZlrly1eLBA"#;

    let parsed = signed_message(qry_str.as_bytes()).unwrap().1;
    let deserialized_qry = Message::try_from(parsed).unwrap();

    witness.process(&vec![deserialized_qry])?;
    let r = witness.respond(signer_arc.clone())?;
    // should respond with reply message
    assert_eq!(r.len(), 1);
    if let Message::Reply(rpy) = &r[0] {
        if let ReplyRoute::Ksn(id, ksn) = &rpy.reply.event.content.data {
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

    Ok(())
}

#[test]
fn test_witness_rotation() -> Result<(), Error> {
    use crate::event::sections::threshold::SignatureThreshold;
    use crate::keri::Keri;
    use std::sync::Mutex;
    use tempfile::Builder;

    let signer_arc = Arc::new(Signer::new());
    let signer_arc2 = Arc::new(Signer::new());

    let mut controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let key_manager = {
            use crate::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new()?))
        };
        Keri::new(Arc::clone(&db_controller), key_manager.clone())?
    };

    assert_eq!(controller.get_state()?, None);

    let first_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::new(root_witness.path(), signer_arc.clone().public_key())?
    };

    let second_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::new(root_witness.path(), signer_arc2.clone().public_key())?
    };

    // Get inception event.
    let inception_event = controller.incept(
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone(),
        ]),
        Some(SignatureThreshold::Simple(2)),
    )?;

    // Shouldn't be accepted in controllers kel, because of missing witness receipts
    assert_eq!(controller.get_state()?, None);

    let receipts = [&first_witness, &second_witness]
        .iter()
        .map(|w| {
            w.process(&vec![Message::Event(inception_event.clone())])
                .unwrap();
            w.respond(signer_arc.clone()).unwrap().clone()
        })
        .flatten()
        .collect::<Vec<_>>();

    // Witness updates state of identifier even if it hasn't all receipts
    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix)?
            .unwrap()
            .sn,
        0
    );
    assert_eq!(
        second_witness
            .get_state_for_prefix(&controller.prefix)?
            .unwrap()
            .sn,
        0
    );

    // process first receipt
    controller.process(&[receipts[0].clone()]).unwrap();

    // Still not fully witnessed
    assert_eq!(controller.get_state()?, None);

    // process second receipt
    controller.process(&[receipts[1].clone()]).unwrap();

    // Now fully witnessed, should be in kel
    assert_eq!(controller.get_state()?.map(|state| state.sn), Some(0));
    assert_eq!(
        controller
            .get_state()?
            .map(|state| state.witness_config.witnesses),
        Some(vec![
            first_witness.prefix.clone(),
            second_witness.prefix.clone()
        ])
    );

    // Process receipts by witnesses.
    first_witness.process(receipts.as_slice())?;
    second_witness.process(receipts.as_slice())?;

    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix)?
            .map(|state| state.sn),
        Some(0)
    );
    assert_eq!(
        second_witness
            .get_state_for_prefix(&controller.prefix)?
            .map(|state| state.sn),
        Some(0)
    );

    let not_fully_witnessed_events = first_witness
        .storage
        .db
        .get_partially_witnessed_events(&controller.prefix);
    assert!(not_fully_witnessed_events.is_none());
    let not_fully_witnessed_events = second_witness
        .storage
        .db
        .get_partially_witnessed_events(&controller.prefix);
    assert!(not_fully_witnessed_events.is_none());

    let rotation_event = controller.rotate(
        None,
        Some(&[second_witness.prefix.clone()]),
        Some(SignatureThreshold::Simple(1)),
    );
    // Rotation not yet accepted by controller, missing receipts
    assert_eq!(controller.get_state()?.unwrap().sn, 0);
    first_witness.process(&[Message::Event(rotation_event?)])?;
    let first_receipt = first_witness.respond(signer_arc)?;
    // Receipt accepted by witness, because his the only designated witness
    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix)?
            .unwrap()
            .sn,
        1
    );

    // process receipt by controller
    controller.process(first_receipt.as_slice())?;
    assert_eq!(controller.get_state()?.unwrap().sn, 1);

    assert_eq!(
        controller
            .get_state()?
            .map(|state| state.witness_config.witnesses),
        Some(vec![first_witness.prefix.clone(),])
    );

    Ok(())
}
