use std::path::Path;
use std::sync::Arc;

use crate::event_message::event_msg_builder::ReceiptBuilder;
use crate::event_message::signed_event_message::{Message, SignedNontransferableReceipt};
use crate::processor::event_storage::EventStorage;
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

pub struct Witness {
    pub prefix: BasicPrefix,
    signer: Signer,
    processor: WitnessProcessor,
    storage: EventStorage,
}

impl Witness {
    pub fn new(path: &Path) -> Result<Self, Error> {
        let signer = Signer::new();
        let (processor, storage) = {
            let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
            (
                WitnessProcessor::new(witness_db.clone()),
                EventStorage::new(witness_db.clone()),
            )
        };
        let prefix = Basic::Ed25519.derive(signer.public_key());
        Ok(Self {
            prefix,
            signer,
            processor,
            storage,
        })
    }

    pub fn process(
        &self,
        event_messages: &[Message],
    ) -> Result<(Vec<SignedNontransferableReceipt>, Vec<Error>), Error> {
        let (oks, errs): (Vec<_>, Vec<_>) = event_messages
            .into_iter()
            .map(|message| self.process_one(message.to_owned()))
            .partition(Result::is_ok);
        let oks: Vec<_> = oks
            .into_iter()
            .map(Result::unwrap)
            .filter(Option::is_some)
            .map(Option::unwrap)
            .collect();
        let errs: Vec<_> = errs.into_iter().map(Result::unwrap_err).collect();

        Ok((oks, errs))
    }

    fn process_one(&self, message: Message) -> Result<Option<SignedNontransferableReceipt>, Error> {
        if let Message::Event(ev) = message.clone() {
            match self.processor.process(message.to_owned()) {
                Ok(_) | Err(Error::NotEnoughReceiptsError) => {
                    // Create witness receipt and add it to db
                    let ser = ev.event_message.serialize()?;
                    let signature = self.signer.sign(&ser)?;
                    // .map_err(|e| Error::ProcessingError(e, sn, prefix.clone()))?;
                    let rcp = ReceiptBuilder::default()
                        .with_receipted_event(ev.event_message)
                        .build()?;

                    let signature = SelfSigning::Ed25519Sha512.derive(signature);

                    let signed_rcp = SignedNontransferableReceipt::new(
                        &rcp,
                        vec![(self.prefix.clone(), signature)],
                    );

                    self.processor
                        .process(Message::NontransferableRct(signed_rcp.clone()))?;
                    Ok(Some(signed_rcp))
                }
                Err(e) => Err(e),
            }
        } else {
            // It's a receipt/query/
            self.processor.process(message.to_owned())?;
            Ok(None)
        }
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_nt_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedNontransferableReceipt>>, Error> {
        Ok(self
            .storage
            .db
            .get_receipts_nt(id)
            .map(|receipts| receipts.collect()))
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

        let signature =
            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?).unwrap());
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

        if kc.verify(&qr.envelope.serialize().unwrap(), &signatures)? {
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
                    .get_state(&i)
                    .unwrap()
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
            w.process_one(Message::Event(inception_event.clone()))
                .unwrap()
                .unwrap()
                .clone()
        })
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
    controller
        .processor
        .process(Message::NontransferableRct(receipts[0].clone()))
        .unwrap();

    // Still not fully witnessed
    assert_eq!(controller.get_state()?, None);

    // process second receipt
    controller
        .processor
        .process(Message::NontransferableRct(receipts[1].clone()))
        .unwrap();

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
    let rcts: Vec<_> = receipts
        .into_iter()
        .map(|r| Message::NontransferableRct(r))
        .collect();
    first_witness.process(&rcts)?;
    second_witness.process(&rcts)?;

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
    let first_receipt = first_witness.process(&[Message::Event(rotation_event?)])?.0;
    // Receipt accepted by witness, because his the only designated witness
    assert_eq!(
        first_witness
            .get_state_for_prefix(&controller.prefix)?
            .unwrap()
            .sn,
        1
    );

    // process receipt by controller
    controller.processor.process(Message::NontransferableRct(
        first_receipt.first().unwrap().to_owned(),
    ))?;
    assert_eq!(controller.get_state()?.unwrap().sn, 1);

    assert_eq!(
        controller
            .get_state()?
            .map(|state| state.witness_config.witnesses),
        Some(vec![first_witness.prefix.clone(),])
    );

    Ok(())
}
