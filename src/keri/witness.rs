use std::path::Path;
use std::sync::Arc;

use crate::event::EventMessage;
use crate::event_message::event_msg_builder::ReceiptBuilder;
use crate::event_message::key_event_message::KeyEvent;
use crate::event_message::signed_event_message::{Message, SignedNontransferableReceipt};
use crate::processor::escrow::default_escrow_bus;
use crate::processor::event_storage::EventStorage;
use crate::processor::notification::{JustNotification, NotificationBus};
use crate::processor::witness_processor::WitnessProcessor;
use crate::query::reply::{ReplyEvent, SignedReply};
use crate::query::{
    key_state_notice::KeyStateNotice,
    query::{QueryData, SignedQuery},
    ReplyType, Route,
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
    signer: Signer,
    processor: WitnessProcessor,
    storage: EventStorage,
    publisher: NotificationBus,
    responder: Arc<Responder>,
}

impl Witness {
    /// Creates a new Witness with a random private key.
    pub fn new(path: &Path) -> Result<Self, Error> {
        let signer = Signer::new();
        Self::init(path, signer)
    }

    /// Creates a new Witness using specified private ED25519_dalek key.
    pub fn new_with_key(path: &Path, priv_key: &[u8]) -> Result<Self, Error> {
        let signer = Signer::new_with_key(priv_key)?;
        Self::init(path, signer)
    }

    fn init(path: &Path, signer: Signer) -> Result<Self, Error> {
        let (processor, storage, mut publisher) = {
            let witness_db = Arc::new(SledEventDatabase::new(path)?);
            (
                WitnessProcessor::new(witness_db.clone()),
                EventStorage::new(witness_db.clone()),
                default_escrow_bus(witness_db.clone()),
            )
        };
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let responder = Arc::new(Responder::default());
        publisher.register_observer(responder.clone(), vec![JustNotification::KeyEventAdded]);

        Ok(Self {
            prefix,
            signer,
            processor,
            storage,
            publisher,
            responder,
        })
    }

    pub fn respond(&self) -> Result<Vec<Message>, Error> {
        let mut response = Vec::new();
        while let Some(event) = self.responder.get_data_to_respond() {
            let non_trans_receipt = self.respond_one(event)?.into();
            response.push(Message::NontransferableRct(non_trans_receipt));
        }
        Ok(response)
    }

    pub fn process(&self, events: &[Message]) -> Result<Option<Vec<Error>>, Error> {
        let (_oks, errs): (Vec<_>, Vec<_>) = events
            .into_iter()
            .map(|message| {
                self.processor
                    .process(message.clone())
                    .and_then(|not| self.publisher.notify(&not))
            })
            .partition(Result::is_ok);

        let errs = if errs.is_empty() {
            None
        } else {
            Some(errs.into_iter().map(Result::unwrap_err).collect())
        };

        Ok(errs)
    }

    fn respond_one(
        &self,
        event_message: EventMessage<KeyEvent>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = self.signer.sign(&ser)?;
        // .map_err(|e| Error::ProcessingError(e, sn, prefix.clone()))?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message)
            .build()?;

        let signature = SelfSigning::Ed25519Sha512.derive(signature);

        let signed_rcp =
            SignedNontransferableReceipt::new(&rcp, vec![(self.prefix.clone(), signature)]);

        self.processor
            .process(Message::NontransferableRct(signed_rcp.clone()))?;
        Ok(signed_rcp)
    }

    pub fn get_kel_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_kel(id)
    }

    pub fn get_receipts_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_nt_receipts(id)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_ksn_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<SignedReply, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or(Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
        let rpy = ReplyEvent::new_reply(
            ksn,
            Route::ReplyKsn(IdentifierPrefix::Basic(self.prefix.clone())),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;

        let signature = SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn process_signed_query(&self, qr: SignedQuery) -> Result<ReplyType, Error> {
        let signatures = qr.signatures;
        // check signatures
        let kc = self
            .storage
            .get_state(&qr.signer)?
            .ok_or(Error::SemanticError("No signer identifier in db".into()))?
            .current;

        if kc.verify(&qr.envelope.serialize()?, &signatures)? {
            // TODO check timestamps
            // unpack and check what's inside
            let route = qr.envelope.event.get_route();
            self.process_query(route, qr.envelope.event.get_query_data())
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    #[cfg(feature = "query")]
    fn process_query(&self, route: Route, qr: QueryData) -> Result<ReplyType, Error> {
        match route {
            Route::Log => {
                Ok(ReplyType::Kel(self.storage.get_kel(&qr.data.i)?.ok_or(
                    Error::SemanticError("No identifier in db".into()),
                )?))
            }
            Route::Ksn => {
                let i = qr.data.i;
                // return reply message with ksn inside
                let state = self
                    .storage
                    .get_state(&i)?
                    .ok_or(Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                let rpy = ReplyEvent::new_reply(
                    ksn,
                    Route::ReplyKsn(IdentifierPrefix::Basic(self.prefix.clone())),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;
                let signature = self.signer.sign(&rpy.serialize()?)?;
                let rpy = SignedReply::new_nontrans(
                    rpy,
                    self.prefix.clone(),
                    SelfSigning::Ed25519Sha512.derive(signature),
                );
                Ok(ReplyType::Rep(rpy))
            }
            _ => todo!(),
        }
    }
}

#[cfg(feature = "query")]
#[test]
pub fn test_query() -> Result<(), Error> {
    use std::convert::TryFrom;

    use crate::event_parsing::message::signed_message;
    use crate::{keri::witness::Witness, query::ReplyType};
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let witness = Witness::new(root.path())?;
    // Process inception event and its receipts. To accept inception event it must be fully witnessed.
    let rcp0 = r#"{"v":"KERI10JSON000091_","t":"rct","d":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","s":"0"}-CABBGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo0BFa01iWtg5DSwsF7XpACh-7OL3q_1lWu4D5uVimx0SFyu6xdCE2gXl-NtX9jY64BIDnTvOSEoY42lk1r6hFoJCw"#;
    let rcp1 = r#"{"v":"KERI10JSON000091_","t":"rct","d":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","s":"0"}-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BPku5B06DZUT6t8rNXCnzJU9HUmFA0tkpjV5deSrqYd4L3gBuPtbSncpaw7MOz0yKwj8dYdO3ejVi8ciMRK5nCA"#;
    let rcp2 = r#"{"v":"KERI10JSON000091_","t":"rct","d":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","s":"0"}-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BrMTUuXnZ1PzhsJgR4XER5eTHDwhBofSV45xMHpryXYRX2fSYgV5T5rIP4vT8NLAxUvunw62-yQo2dVRlOnMKCg"#;
    let icp_str = r#"{"v":"KERI10JSON0001ac_","t":"icp","d":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk","s":"0","kt":"1","k":["DxH8nLaGIMllBp0mvGdN6JtbNuGRPyHb5i80bTojnP9A"],"n":"EmJ-3Y0pM0ogX8401rEziJhpql567YEdHDlylwfnxNIM","bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-AABAAGwlsKbtQjGUoKlYsBRksx5KmAiXWtNakJkxmxizV0aoN4d_GwtmnbNwpuuggc3CmoftruHIo_Q9CbWw-lUitDA"#;
    let to_process: Vec<_> = [rcp0, rcp1, rcp2, icp_str]
        .iter()
        .map(|event| {
            let parsed = signed_message(event.as_bytes()).unwrap().1;
            Message::try_from(parsed).unwrap()
        })
        .collect();
    witness.process(to_process.as_slice()).unwrap();

    let qry_str = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EEFpGGlsAGe51BgyebzDUAs4ewWYz1HO9rytYVaxDo3c","dt":"2022-01-13T15:53:32.020709+00:00","r":"ksn","rr":"","q":{"i":"ESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk"}}-VAj-HABESZVhKqI9F_UGQAQRYGNwqqdKOMjez7aupox9UZwZcBk-AABAAMOLeXG1ClCtSPP4hhtvyoWMLOvMvaiveHCepL3zh1OQcAyn2GzEh2TwjKFyKFGBXD6-blmvg8M8hDMr-yjv6Bw"#;
    let parsed = signed_message(qry_str.as_bytes()).unwrap().1;
    let deserialized_qy = Message::try_from(parsed).unwrap();

    if let Message::Query(qry) = deserialized_qy {
        let res = witness.process_signed_query(qry)?;
        assert!(matches!(res, ReplyType::Rep(_)));
    } else {
        assert!(false)
    }

    Ok(())
}

#[test]
fn test_witness_rotation() -> Result<(), Error> {
    use crate::event::sections::threshold::SignatureThreshold;
    use crate::keri::Keri;
    use std::sync::Mutex;
    use tempfile::Builder;

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
        Witness::new(root_witness.path())?
    };

    let second_witness = {
        let root_witness = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root_witness.path()).unwrap();
        Witness::new(root_witness.path())?
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
            w.respond().unwrap().clone()
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
    let first_receipt = first_witness.respond()?;
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
