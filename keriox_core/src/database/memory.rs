use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use said::SelfAddressingIdentifier;

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    database::{
        timestamped::{Timestamped, TimestampedSignedEventMessage},
        EscrowCreator, EscrowDatabase, EventDatabase, LogDatabase, QueryParameters,
        SequencedEventDatabase,
    },
    error::Error,
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::{IdentifierPrefix, IndexedSignature},
    state::IdentifierState,
};

/// In-memory implementation of EventDatabase for testing and validation.
pub struct MemoryDatabase {
    /// Events stored by identifier prefix, ordered by sn
    events: RwLock<HashMap<IdentifierPrefix, Vec<TimestampedSignedEventMessage>>>,
    /// Key state per identifier
    states: RwLock<HashMap<IdentifierPrefix, IdentifierState>>,
    /// Transferable receipts by (id, sn)
    receipts_t: RwLock<HashMap<(IdentifierPrefix, u64), Vec<Transferable>>>,
    /// Non-transferable receipts by (id, sn)
    receipts_nt: RwLock<HashMap<(IdentifierPrefix, u64), Vec<SignedNontransferableReceipt>>>,
    /// Log database
    log_db: Arc<MemoryLogDatabase>,
    /// Escrow counter for creating unique table names
    escrow_db: Arc<RwLock<HashMap<&'static str, Arc<MemorySequencedEventDb>>>>,
    #[cfg(feature = "query")]
    replies: RwLock<HashMap<(IdentifierPrefix, IdentifierPrefix), SignedReply>>,
}

impl MemoryDatabase {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            states: RwLock::new(HashMap::new()),
            receipts_t: RwLock::new(HashMap::new()),
            receipts_nt: RwLock::new(HashMap::new()),
            log_db: Arc::new(MemoryLogDatabase::new()),
            escrow_db: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(feature = "query")]
            replies: RwLock::new(HashMap::new()),
        }
    }
}

impl EventDatabase for MemoryDatabase {
    type Error = Error;
    type LogDatabaseType = MemoryLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        // Update key state
        let current_state = self
            .states
            .read()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default();
        let new_state = current_state.apply(&event.event_message)?;
        self.states.write().unwrap().insert(id.clone(), new_state);

        // Log the event
        self.log_db.log_event_internal(&event);

        // Store in KEL
        let timestamped = Timestamped::new(event);
        self.events
            .write()
            .unwrap()
            .entry(id.clone())
            .or_default()
            .push(timestamped);

        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let sn = receipt.body.sn;
        let transferable = Transferable::Seal(receipt.validator_seal, receipt.signatures);
        self.receipts_t
            .write()
            .unwrap()
            .entry((id.clone(), sn))
            .or_default()
            .push(transferable);
        Ok(())
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let sn = receipt.body.sn;
        self.receipts_nt
            .write()
            .unwrap()
            .entry((id.clone(), sn))
            .or_default()
            .push(receipt);
        Ok(())
    }

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        self.states.read().unwrap().get(id).cloned()
    }

    fn get_kel_finalized_events(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        let events = self.events.read().unwrap();
        match params {
            QueryParameters::All { id } => {
                events.get(id).cloned().map(|v| v.into_iter())
            }
            QueryParameters::BySn { ref id, sn } => {
                events.get(id).map(|evts| {
                    evts.iter()
                        .filter(move |e| e.signed_event_message.event_message.data.get_sn() == sn)
                        .cloned()
                        .collect::<Vec<_>>()
                        .into_iter()
                })
            }
            QueryParameters::Range {
                ref id,
                start,
                limit,
            } => events.get(id).map(|evts| {
                evts.iter()
                    .filter(move |e| {
                        let sn = e.signed_event_message.event_message.data.get_sn();
                        sn >= start && sn < start + limit
                    })
                    .cloned()
                    .collect::<Vec<_>>()
                    .into_iter()
            }),
        }
    }

    fn get_receipts_t(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>> {
        let receipts = self.receipts_t.read().unwrap();
        match params {
            QueryParameters::BySn { ref id, sn } => {
                receipts.get(&(id.clone(), sn)).cloned().map(|v| v.into_iter())
            }
            _ => None,
        }
    }

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        let receipts = self.receipts_nt.read().unwrap();
        match params {
            QueryParameters::BySn { ref id, sn } => {
                receipts.get(&(id.clone(), sn)).cloned().map(|v| v.into_iter())
            }
            _ => None,
        }
    }

    fn accept_to_kel(&self, _event: &KeriEvent<KeyEvent>) -> Result<(), Self::Error> {
        // In redb, this saves the event to KEL tables. For memory, events
        // are already in the events map from add_kel_finalized_event.
        Ok(())
    }

    #[cfg(feature = "query")]
    fn save_reply(&self, reply: SignedReply) -> Result<(), Self::Error> {
        let id = reply.reply.get_prefix();
        let signer = reply
            .signature
            .get_signer()
            .ok_or_else(|| Error::SemanticError("Missing signer".into()))?;
        self.replies
            .write()
            .unwrap()
            .insert((id, signer), reply);
        Ok(())
    }

    #[cfg(feature = "query")]
    fn get_reply(
        &self,
        id: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
    ) -> Option<SignedReply> {
        self.replies
            .read()
            .unwrap()
            .get(&(id.clone(), from_who.clone()))
            .cloned()
    }
}

/// In-memory log database for storing events by digest.
pub struct MemoryLogDatabase {
    events: RwLock<HashMap<SelfAddressingIdentifier, TimestampedSignedEventMessage>>,
    signatures: RwLock<HashMap<SelfAddressingIdentifier, Vec<IndexedSignature>>>,
    nontrans_couplets: RwLock<HashMap<SelfAddressingIdentifier, Vec<Nontransferable>>>,
    trans_receipts: RwLock<HashMap<SelfAddressingIdentifier, Vec<Transferable>>>,
}

impl MemoryLogDatabase {
    pub fn new() -> Self {
        Self {
            events: RwLock::new(HashMap::new()),
            signatures: RwLock::new(HashMap::new()),
            nontrans_couplets: RwLock::new(HashMap::new()),
            trans_receipts: RwLock::new(HashMap::new()),
        }
    }

    fn log_event_internal(&self, event: &SignedEventMessage) {
        if let Ok(digest) = event.event_message.digest() {
            let timestamped = Timestamped::new(event.clone());
            self.events.write().unwrap().insert(digest.clone(), timestamped);
            self.signatures
                .write()
                .unwrap()
                .insert(digest, event.signatures.clone());
        }
    }

    fn log_receipt_internal(&self, receipt: &SignedNontransferableReceipt) {
        let digest = receipt.body.receipted_event_digest.clone();
        self.nontrans_couplets
            .write()
            .unwrap()
            .entry(digest)
            .or_default()
            .extend(receipt.signatures.clone());
    }
}

impl LogDatabase<'static> for MemoryLogDatabase {
    type DatabaseType = ();
    type Error = Error;
    type TransactionType = ();

    fn new(_db: Arc<Self::DatabaseType>) -> Result<Self, Self::Error> {
        Ok(Self::new())
    }

    fn log_event(
        &self,
        _txn: &Self::TransactionType,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log_event_internal(signed_event);
        Ok(())
    }

    fn log_event_with_new_transaction(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log_event_internal(signed_event);
        Ok(())
    }

    fn log_receipt(
        &self,
        _txn: &Self::TransactionType,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        self.log_receipt_internal(signed_receipt);
        Ok(())
    }

    fn log_receipt_with_new_transaction(
        &self,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        self.log_receipt_internal(signed_receipt);
        Ok(())
    }

    fn get_signed_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, Self::Error> {
        Ok(self.events.read().unwrap().get(said).cloned())
    }

    fn get_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, Self::Error> {
        Ok(self
            .events
            .read()
            .unwrap()
            .get(said)
            .map(|t| t.signed_event_message.event_message.clone()))
    }

    fn get_signatures(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, Self::Error> {
        Ok(self
            .signatures
            .read()
            .unwrap()
            .get(said)
            .cloned()
            .map(|v| v.into_iter()))
    }

    fn get_nontrans_couplets(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, Self::Error> {
        Ok(self
            .nontrans_couplets
            .read()
            .unwrap()
            .get(said)
            .cloned()
            .map(|v| v.into_iter()))
    }

    fn get_trans_receipts(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, Self::Error> {
        Ok(self
            .trans_receipts
            .read()
            .unwrap()
            .get(said)
            .cloned()
            .unwrap_or_default()
            .into_iter())
    }

    fn remove_nontrans_receipt(
        &self,
        _txn_mode: &Self::TransactionType,
        said: &SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        let to_remove: Vec<_> = nontrans.into_iter().collect();
        if let Some(existing) = self.nontrans_couplets.write().unwrap().get_mut(said) {
            existing.retain(|n| !to_remove.contains(n));
        }
        Ok(())
    }

    fn remove_nontrans_receipt_with_new_transaction(
        &self,
        said: &SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        self.remove_nontrans_receipt(&(), said, nontrans)
    }
}

/// In-memory sequenced event database for escrow storage.
pub struct MemorySequencedEventDb {
    data: RwLock<HashMap<(IdentifierPrefix, u64), Vec<SelfAddressingIdentifier>>>,
}

impl MemorySequencedEventDb {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }
}

impl SequencedEventDatabase for MemorySequencedEventDb {
    type DatabaseType = ();
    type Error = Error;
    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(_db: Arc<Self::DatabaseType>, _table_name: &'static str) -> Result<Self, Self::Error> {
        Ok(Self::new())
    }

    fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        self.data
            .write()
            .unwrap()
            .entry((identifier.clone(), sn))
            .or_default()
            .push(digest.clone());
        Ok(())
    }

    fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        let data = self.data.read().unwrap();
        let items = data
            .get(&(identifier.clone(), sn))
            .cloned()
            .unwrap_or_default();
        Ok(Box::new(items.into_iter()))
    }

    fn get_greater_than(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        let data = self.data.read().unwrap();
        let items: Vec<_> = data
            .iter()
            .filter(|((id, s), _)| id == identifier && *s >= sn)
            .flat_map(|(_, v)| v.clone())
            .collect();
        Ok(Box::new(items.into_iter()))
    }

    fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        if let Some(v) = self.data.write().unwrap().get_mut(&(identifier.clone(), sn)) {
            v.retain(|d| d != said);
        }
        Ok(())
    }
}

/// In-memory escrow database.
pub struct MemoryEscrowDb {
    sequenced: Arc<MemorySequencedEventDb>,
    log: Arc<MemoryLogDatabase>,
}

impl EscrowDatabase for MemoryEscrowDb {
    type EscrowDatabaseType = ();
    type LogDatabaseType = MemoryLogDatabase;
    type Error = Error;
    type EventIter = std::vec::IntoIter<SignedEventMessage>;

    fn new(
        _escrow: Arc<
            dyn SequencedEventDatabase<
                DatabaseType = Self::EscrowDatabaseType,
                Error = Self::Error,
                DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>,
            >,
        >,
        log: Arc<Self::LogDatabaseType>,
    ) -> Self {
        // We won't use this constructor in practice; use from_parts instead
        Self {
            sequenced: Arc::new(MemorySequencedEventDb::new()),
            log,
        }
    }

    fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        self.sequenced.insert(id, sn, event_digest)
    }

    fn insert(&self, event: &SignedEventMessage) -> Result<(), Self::Error> {
        let digest = event.event_message.digest()?;
        let sn = event.event_message.data.get_sn();
        let id = event.event_message.data.get_prefix();
        self.sequenced.insert(&id, sn, &digest)?;
        self.log.log_event_internal(event);
        Ok(())
    }

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        let digest = event.event_message.digest()?;
        self.sequenced.insert(id, sn, &digest)?;
        self.log.log_event_internal(event);
        Ok(())
    }

    fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let digests = self.sequenced.get(identifier, sn)?;
        let events: Vec<_> = digests
            .filter_map(|d| {
                self.log
                    .get_signed_event(&d)
                    .ok()
                    .flatten()
                    .map(|t| t.signed_event_message)
            })
            .collect();
        Ok(events.into_iter())
    }

    fn get_from_sn(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let digests = self.sequenced.get_greater_than(identifier, sn)?;
        let events: Vec<_> = digests
            .filter_map(|d| {
                self.log
                    .get_signed_event(&d)
                    .ok()
                    .flatten()
                    .map(|t| t.signed_event_message)
            })
            .collect();
        Ok(events.into_iter())
    }

    fn remove(&self, event: &KeriEvent<KeyEvent>) {
        if let Ok(digest) = event.digest() {
            let sn = event.data.get_sn();
            let id = event.data.get_prefix();
            let _ = self.sequenced.remove(&id, sn, &digest);
        }
    }

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<bool, Self::Error> {
        let digests = self.sequenced.get(id, sn)?;
        Ok(digests.collect::<Vec<_>>().contains(digest))
    }
}

impl EscrowCreator for MemoryDatabase {
    type EscrowDatabaseType = MemoryEscrowDb;

    fn create_escrow_db(&self, table_name: &'static str) -> Self::EscrowDatabaseType {
        let seq = Arc::new(MemorySequencedEventDb::new());
        self.escrow_db
            .write()
            .unwrap()
            .insert(table_name, seq.clone());
        MemoryEscrowDb {
            sequenced: seq,
            log: self.log_db.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryFrom, sync::Arc};

    use cesrox::parse;

    use super::MemoryDatabase;
    use crate::{
        error::Error,
        event_message::signed_event_message::{Message, Notice},
        processor::{
            basic_processor::BasicProcessor, event_storage::EventStorage, Processor,
        },
    };

    #[test]
    fn test_memory_db_process_icp() -> Result<(), Error> {
        let db = Arc::new(MemoryDatabase::new());
        let processor = BasicProcessor::new(db.clone(), None);
        let storage = EventStorage::new(db.clone());

        // Inception event from keripy test_multisig_digprefix
        let icp_raw = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let parsed = parse(icp_raw).unwrap().1;
        let deserialized_icp = Message::try_from(parsed).unwrap();

        let id = match &deserialized_icp {
            Message::Notice(Notice::Event(e)) => e.event_message.data.get_prefix(),
            _ => panic!("unexpected message type"),
        };

        // Process inception event
        processor.process(&deserialized_icp)?;

        // Verify state was created
        let state = storage.get_state(&id);
        assert!(state.is_some());
        let state = state.unwrap();
        assert_eq!(state.sn, 0);
        assert_eq!(state.current.public_keys.len(), 3);

        // Verify KEL has the event
        let kel = storage.get_kel_messages(&id)?;
        assert!(kel.is_some());
        assert_eq!(kel.unwrap().len(), 1);

        Ok(())
    }
}
