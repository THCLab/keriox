use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use super::{prelude::Message, process_message};
use crate::{
    controller::event_generator,
    database::{escrow::EscrowDb, SledEventDatabase},
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    event_message::signed_event_message::{Notice, Op, SignedEventMessage},
    event_parsing::{message::key_event_message, EventType},
    oobi::{OobiManager, Role},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
    processor::{
        basic_processor::BasicProcessor, escrow::default_escrow_bus, event_storage::EventStorage,
        Processor,
    },
    query::{
        query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
        reply_event::SignedReply,
    },
    signer::KeyManager,
    state::IdentifierState,
};

/// Helper struct for events generation, signing and processing.
/// Used in tests.
pub struct SimpleController<K: KeyManager + 'static> {
    prefix: IdentifierPrefix,
    pub key_manager: Arc<Mutex<K>>,
    processor: BasicProcessor,
    oobi_manager: OobiManager,
    pub storage: EventStorage,
}

impl<K: KeyManager> SimpleController<K> {
    // incept a state and keys
    pub fn new(
        db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        key_manager: Arc<Mutex<K>>,
        oobi_db_path: &Path,
    ) -> Result<SimpleController<K>, Error> {
        let (not_bus, _) = default_escrow_bus(db.clone(), escrow_db);
        let processor = BasicProcessor::new(db.clone(), Some(not_bus));

        Ok(SimpleController {
            prefix: IdentifierPrefix::default(),
            key_manager,
            oobi_manager: OobiManager::new(oobi_db_path),
            processor,
            storage: EventStorage::new(db),
        })
    }

    /// Getter of the instance prefix
    ///
    pub fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    pub fn incept(
        &mut self,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
    ) -> Result<SignedEventMessage, Error> {
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let icp = event_generator::incept(
            vec![Basic::Ed25519.derive(km.public_key())],
            vec![Basic::Ed25519.derive(km.next_public_key())],
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
        )
        .unwrap();
        let signature = km.sign(icp.as_bytes())?;
        let (_, key_event) = key_event_message(icp.as_bytes()).unwrap();
        let signed = if let EventType::KeyEvent(icp) = key_event {
            icp.sign(
                vec![AttachedSignaturePrefix::new(
                    SelfSigning::Ed25519Sha512,
                    signature,
                    0,
                )],
                None,
                None,
            )
        } else {
            unreachable!()
        };

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        self.prefix = signed.event_message.event.get_prefix();
        // No need to generate receipt

        Ok(signed)
    }

    pub fn query(&self, prefix: &IdentifierPrefix) -> Result<Op, Error> {
        let query_args = QueryArgs {
            s: None,
            i: prefix.clone(),
            src: None,
        };

        let qry = QueryEvent::new_query(
            QueryRoute::Ksn {
                args: query_args,
                reply_route: String::from(""),
            },
            SerializationFormats::JSON,
            &SelfAddressing::Blake3_256,
        )?;

        // sign message by bob
        let signature = AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            Arc::clone(&self.key_manager)
                .lock()
                .unwrap()
                .sign(&serde_json::to_vec(&qry).unwrap())?,
            0,
        );
        // Qry message signed by Bob
        Ok(Op::Query(SignedQuery::new(
            qry,
            self.prefix().clone(),
            vec![signature],
        )))
    }

    pub fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<Op, Error> {
        let end_role =
            event_generator::generate_end_role(&self.prefix(), watcher_id, Role::Watcher, true)
                .unwrap();
        let sed: Vec<u8> = end_role.serialize()?;
        let sig = self.key_manager.clone().lock().unwrap().sign(&sed)?;
        let att_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

        let oobi_rpy = SignedReply::new_trans(
            end_role,
            self.storage
                .get_last_establishment_event_seal(self.prefix())?
                .unwrap(),
            vec![att_sig],
        );
        self.oobi_manager.process_oobi(&oobi_rpy).unwrap();
        let signed_rpy = Op::Reply(oobi_rpy);

        Ok(signed_rpy)
    }

    pub fn rotate(
        &mut self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<u64>,
    ) -> Result<SignedEventMessage, Error> {
        let rot = self.make_rotation(witness_to_add, witness_to_remove, witness_threshold)?;
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let signature = km.sign(rot.as_bytes())?;

        let (_, key_event) = key_event_message(rot.as_bytes()).unwrap();

        let signed = if let EventType::KeyEvent(rot) = key_event {
            rot.sign(
                vec![AttachedSignaturePrefix::new(
                    SelfSigning::Ed25519Sha512,
                    signature,
                    0,
                )],
                None,
                None,
            )
        } else {
            unreachable!()
        };

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        Ok(signed)
    }

    fn make_rotation(
        &self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<u64>,
    ) -> Result<String, Error> {
        let mut km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        km.rotate()?;
        let state = self
            .storage
            .get_state(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

        Ok(event_generator::rotate(
            state,
            vec![Basic::Ed25519.derive(km.public_key())],
            vec![Basic::Ed25519.derive(km.next_public_key())],
            witness_to_add.unwrap_or_default().to_vec(),
            witness_to_remove.unwrap_or_default().into(),
            witness_threshold.unwrap_or(0),
        )
        .unwrap())
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), Error> {
        let (_process_ok, _process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                process_message(
                    message.clone(),
                    &self.oobi_manager,
                    &self.processor,
                    &self.storage,
                )
            })
            .partition(Result::is_ok);

        Ok(())
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(&self.prefix)
    }
}
