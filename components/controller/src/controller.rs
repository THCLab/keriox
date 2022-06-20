use std::{
    convert::TryFrom,
    path::Path,
    sync::{Arc, Mutex},
};

use keri::{
    actor::prelude::*,
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::{
        event_data::{EventData, InteractionEvent},
        receipt::Receipt,
        sections::{
            seal::{DigestSeal, EventSeal, Seal},
            threshold::SignatureThreshold,
        },
        Event, EventMessage, SerializationFormats,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder,
        key_event_message::KeyEvent,
        signed_event_message::{
            Message, Notice, SignedEventMessage, SignedNontransferableReceipt,
            SignedTransferableReceipt,
        },
        EventTypeTag,
    },
    event_parsing::message::{signed_event_stream, signed_message},
    oobi::OobiManager,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::KeyManager,
    state::IdentifierState,
};

#[cfg(feature = "oobi")]
use crate::oobi::OobiManager;

pub struct Controller<K: KeyManager + 'static> {
    prefix: IdentifierPrefix,
    key_manager: Arc<Mutex<K>>,
    processor: BasicProcessor,
    oobi_manager: OobiManager,
    pub storage: EventStorage,
}

impl<K: KeyManager> Controller<K> {
    // incept a state and keys
    pub fn new(
        db: Arc<SledEventDatabase>,
        key_manager: Arc<Mutex<K>>,
        oobi_db_path: &Path,
    ) -> Result<Controller<K>, Error> {
        let processor = BasicProcessor::new(db.clone());

        Ok(Controller {
            prefix: IdentifierPrefix::default(),
            key_manager,
            processor,
            oobi_manager: OobiManager::new(oobi_db_path),
            storage: EventStorage::new(db),
        })
    }

    /// Getter of the instance prefix
    ///
    pub fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    /// Getter of ref to owned `KeyManager` instance
    ///
    pub fn key_manager(&self) -> Arc<Mutex<K>> {
        self.key_manager.clone()
    }

    // Getter of the DB instance behind own processor
    ///
    pub fn db(&self) -> Arc<SledEventDatabase> {
        Arc::clone(&self.storage.db)
    }

    #[cfg(feature = "oobi")]
    pub fn register_oobi_manager(&mut self, oobi_manager: Arc<OobiManager>) -> Result<(), Error> {
        self.notification_bus
            .register_observer(oobi_manager, vec![JustNotification::GotOobi]);
        Ok(())
    }

    pub fn incept(
        &mut self,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<SignatureThreshold>,
    ) -> Result<SignedEventMessage, Error> {
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_prefix(&self.prefix)
            .with_keys(vec![Basic::Ed25519.derive(km.public_key())])
            .with_next_keys(vec![Basic::Ed25519.derive(km.next_public_key())])
            .with_witness_list(&initial_witness.unwrap_or_default())
            .with_witness_threshold(&witness_threshold.unwrap_or(SignatureThreshold::Simple(0)))
            .build()?;

        let signed = icp.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                km.sign(&icp.serialize()?)?,
                0,
            )],
            None,
            None,
        );

        process_notice(Notice::Event(signed.clone()), &self.processor)?;

        self.prefix = icp.event.get_prefix();
        // No need to generate receipt

        Ok(signed)
    }

    /// Interacts with peer identifier via generation of a `Seal`
    /// Seal gets added to our KEL db and returned back as `SignedEventMessage`
    ///
    pub fn interact(&self, peer: IdentifierPrefix) -> Result<SignedEventMessage, Error> {
        let next_sn = match self.storage.db.get_kel_finalized_events(&self.prefix) {
            Some(mut events) => match events.next_back() {
                Some(db_event) => db_event.signed_event_message.event_message.event.get_sn() + 1,
                None => return Err(Error::InvalidIdentifierStat),
            },
            None => return Err(Error::InvalidIdentifierStat),
        };
        let (pref, seal) = match peer {
            IdentifierPrefix::SelfAddressing(pref) => {
                (pref.clone(), Seal::Digest(DigestSeal { dig: pref }))
            }
            _ => {
                return Err(Error::SemanticError(
                    "Can interact with SelfAdressing prefixes only".into(),
                ))
            }
        };
        let event = Event::new(
            self.prefix.clone(),
            next_sn,
            EventData::Ixn(InteractionEvent::new(pref, vec![seal])),
        )
        .to_message(SerializationFormats::JSON, &SelfAddressing::Blake3_256)?;
        let serialized = event.serialize()?;
        let signature = self
            .key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .sign(&serialized)?;
        let asp = AttachedSignaturePrefix::new(
            SelfSigning::ECDSAsecp256k1Sha256,
            signature,
            0, // TODO: what is this?
        );
        let signed = SignedEventMessage::new(&event, vec![asp], None, None);
        self.storage
            .db
            .add_kel_finalized_event(signed.clone(), &self.prefix)?;
        Ok(signed)
    }

    pub fn rotate(
        &mut self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<SignatureThreshold>,
    ) -> Result<SignedEventMessage, Error> {
        self.key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .rotate()?;
        let rot = self.make_rotation(witness_to_add, witness_to_remove, witness_threshold)?;
        let rot = rot.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager
                    .lock()
                    .map_err(|_| Error::MutexPoisoned)?
                    .sign(&rot.serialize()?)?,
                0,
            )],
            None,
            None,
        );

        process_notice(Notice::Event(rot.clone()), &self.processor)?;

        Ok(rot)
    }

    fn make_rotation(
        &self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<SignatureThreshold>,
    ) -> Result<EventMessage<KeyEvent>, Error> {
        let state = self
            .storage
            .get_state(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;
        match self.key_manager.lock() {
            Ok(kv) => EventMsgBuilder::new(EventTypeTag::Rot)
                .with_prefix(&self.prefix)
                .with_sn(state.sn + 1)
                .with_previous_event(&state.last_event_digest)
                .with_keys(vec![Basic::Ed25519.derive(kv.public_key())])
                .with_next_keys(vec![Basic::Ed25519.derive(kv.next_public_key())])
                .with_witness_to_add(witness_to_add.unwrap_or_default())
                .with_witness_to_remove(witness_to_remove.unwrap_or_default())
                .with_witness_threshold(&witness_threshold.unwrap_or(SignatureThreshold::Simple(0)))
                .build(),
            Err(_) => Err(Error::MutexPoisoned),
        }
    }

    pub fn make_ixn(&mut self, payload: Option<&str>) -> Result<SignedEventMessage, Error> {
        let seal_list = match payload {
            Some(payload) => {
                vec![Seal::Digest(DigestSeal {
                    dig: SelfAddressing::Blake3_256.derive(payload.as_bytes()),
                })]
            }
            None => vec![],
        };
        let state = self
            .storage
            .get_state(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

        let ev = EventMsgBuilder::new(EventTypeTag::Ixn)
            .with_prefix(&self.prefix)
            .with_sn(state.sn + 1)
            .with_previous_event(&state.last_event_digest)
            .with_seal(seal_list)
            .build()?;

        let ixn = ev.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                self.key_manager
                    .lock()
                    .map_err(|_| Error::MutexPoisoned)?
                    .sign(&ev.serialize()?)?,
                0,
            )],
            None,
            None,
        );

        process_notice(Notice::Event(ixn.clone()), &self.processor)?;

        Ok(ixn)
    }

    /// Process and respond to single event
    ///
    pub fn respond_single(&self, msg: &[u8]) -> Result<(IdentifierPrefix, Vec<u8>), Error> {
        let parsed = signed_message(msg).map_err(|e| Error::DeserializeError(e.to_string()))?;
        match Message::try_from(parsed.1) {
            Err(e) => Err(Error::DeserializeError(e.to_string())),
            Ok(event) => {
                let prefix = event.get_prefix();
                process_message(event, &self.oobi_manager, &self.processor, &self.storage)?;
                match self.get_state_for_prefix(&prefix)? {
                    None => Err(Error::InvalidIdentifierStat),
                    Some(state) => Ok((prefix, serde_json::to_vec(&state)?)),
                }
            }
        }
    }

    pub fn parse_and_process(&self, msg: &[u8]) -> Result<(), Error> {
        let mut events = signed_event_stream(msg)
            .map_err(|e| Error::DeserializeError(e.to_string()))?
            .1
            .into_iter()
            .map(Message::try_from);
        events.try_for_each(|msg| {
            let msg = msg?;
            self.process(&vec![msg.clone()])?;
            // check if receipts are attached
            if let Message::Notice(Notice::Event(ev)) = msg {
                if let Some(witness_receipts) = ev.witness_receipts {
                    // Create and process witness receipts
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
                    self.process(&vec![Message::Notice(Notice::NontransferableRct(signed_receipt))])
                } else {
                    Ok(())
                }
            } else {
                Ok(())
            }
        })
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

    pub fn make_rct(
        &self,
        event: EventMessage<KeyEvent>,
    ) -> Result<SignedTransferableReceipt, Error> {
        let ser = event.serialize()?;
        let signature = self
            .key_manager
            .lock()
            .map_err(|_| Error::MutexPoisoned)?
            .sign(&ser)?;
        let validator_event_seal = self
            .storage
            .get_last_establishment_event_seal(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("No establishment event seal".into()))?;
        let rcp = Receipt {
            prefix: event.event.get_prefix(),
            sn: event.event.get_sn(),
            receipted_event_digest: event.get_digest(),
        }
        .to_message(SerializationFormats::JSON)?;

        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_rcp = SignedTransferableReceipt::new(rcp, validator_event_seal, signatures);

        process_notice(
            Notice::TransferableRct(signed_rcp.clone()),
            &self.processor,
        )?;

        Ok(signed_rcp)
    }

    /// Create `SignedNontransferableReceipt` for given `EventMessage`
    /// This will actually process and generate receipt if we are added as witness
    /// Generated receipt will be stored into `ntp` DB table under sender's identifier
    /// Ignore and return `Error::SemanticError` with description why no receipt returned
    ///
    /// # Parameters
    /// * `message` - `EventMessage` we are to process
    ///
    pub fn make_ntr(
        &self,
        message: EventMessage<KeyEvent>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        let our_bp = match &self.prefix {
            IdentifierPrefix::Basic(prefix) => prefix,
            _ => {
                return Err(Error::SemanticError(
                    "we are not a witness - our prefix is not Basic".into(),
                ))
            }
        };
        match &message.event.get_event_data() {
            // ICP requires check if we are in initial witnesses only
            EventData::Icp(evt) => {
                if !evt.witness_config.initial_witnesses.contains(our_bp) {
                    return Err(Error::SemanticError("we are not in a witness list.".into()));
                }
                self.generate_ntr(message)
            }
            EventData::Rot(evt) => {
                if !evt.witness_config.prune.contains(our_bp) {
                    if evt.witness_config.graft.contains(our_bp) {
                        // FIXME: logic for already witnessed identifier required
                        self.generate_ntr(message)
                    } else {
                        Err(Error::SemanticError(
                            "event does not change our status as a witness".into(),
                        ))
                    }
                } else if evt.witness_config.prune.contains(our_bp) {
                    self.storage
                        .db
                        .remove_receipts_nt(&message.event.get_prefix())?;
                    Err(Error::SemanticError(
                        "we were removed. no receipt to generate".into(),
                    ))
                } else {
                    Err(Error::SemanticError(
                        "event without witness modifications".into(),
                    ))
                }
            }
            _ => Err(Error::SemanticError(
                "event without witness modifications".into(),
            )),
        }
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(&self.prefix)
    }

    pub fn get_kel(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_kel(id)
    }

    pub fn get_nt_receipts(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingPrefix,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        self.storage.get_nt_receipts(id, sn, digest)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_state_for_seal(&self, seal: &EventSeal) -> Result<Option<IdentifierState>, Error> {
        self.storage.compute_state_at_sn(&seal.prefix, seal.sn)
    }

    fn generate_ntr(
        &self,
        message: EventMessage<KeyEvent>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        let signature;
        let bp;
        match self.key_manager.lock() {
            Ok(km) => {
                signature = km.sign(&message.serialize()?)?;
                bp = BasicPrefix::new(Basic::Ed25519, km.public_key());
            }
            Err(_) => return Err(Error::MutexPoisoned),
        }
        let ssp = SelfSigningPrefix::new(SelfSigning::Ed25519Sha512, signature);
        let rcp = Receipt {
            prefix: message.event.get_prefix(),
            sn: message.event.get_sn(),
            receipted_event_digest: SelfAddressing::Blake3_256.derive(&message.serialize()?),
        }
        .to_message(SerializationFormats::JSON)?;
        let ntr = SignedNontransferableReceipt::new(&rcp, Some(vec![(bp, ssp)]), None);
        self.storage
            .db
            .add_receipt_nt(ntr.clone(), &message.event.get_prefix())?;
        Ok(ntr)
    }
}
