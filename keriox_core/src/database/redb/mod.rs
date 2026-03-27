pub mod escrow_database;
#[cfg(feature = "query")]
pub(crate) mod ksn_log;
pub mod loging;
pub(crate) use super::rkyv_adapter;

/// Kel storage. (identifier, sn) -> event digest
/// The `KELS` table links an identifier and sequence number to the digest of an event,
/// referencing the actual event stored in the `EVENTS` table.
const KELS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kels");

/// Key states storage. (identifier) -> key state
/// The `KEY_STATES` table stores the state of each identifier, which is updated
/// as events are processed.
const KEY_STATES: TableDefinition<&str, &[u8]> = TableDefinition::new("key_states");

use std::{path::Path, sync::Arc, u64};

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
#[cfg(feature = "query")]
use ksn_log::AcceptedKsn;
use loging::LogDatabase;
use redb::{Database, ReadableTable, TableDefinition};
use said::{sad::SerializationFormats, SelfAddressingIdentifier};

use crate::{
    event::{receipt::Receipt, KeyEvent},
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::IdentifierPrefix,
    state::IdentifierState,
};
use cesrox::primitives::CesrPrimitive;

use super::{timestamped, EventDatabase, LogDatabase as LogDatabaseTrait, QueryParameters};

#[derive(Debug, thiserror::Error)]
pub enum RedbError {
    #[error("Failed to create database. Reason: {0}")]
    DatabaseCreationFiled(#[from] redb::DatabaseError),
    #[error("Failed to save to database. Reason: {0}")]
    TransactionFiled(#[from] redb::TransactionError),
    #[error("Failed to save to database. Reason: {0}")]
    CommitFiled(#[from] redb::CommitError),
    #[error("Table opening error. Reason: {0}")]
    TableError(#[from] redb::TableError),
    #[error("Saving element error. Reason: {0}")]
    InsertingError(#[from] redb::StorageError),
    #[error("Retrieving element error. Reason: {0}")]
    RetrievingError(redb::Error),
    #[error("Value format error")]
    WrongValue,
    #[error("Key format error")]
    WrongKey(#[from] KeyError),
    #[error("No event for digest {0} found")]
    NotFound(SelfAddressingIdentifier),
    #[error("No digest in provided event")]
    MissingDigest,
    #[error("Rkyv error: {0}")]
    Rkyv(#[from] rkyv::rancor::Error),
    #[error("Already saved: {0}")]
    AlreadySaved(SelfAddressingIdentifier),
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Can't parse said in key")]
    UnparsableSaid,
    #[error("Can't parse index in key")]
    UnparsableIndex,
}

/// Represents the mode for executing database transactions.
pub enum WriteTxnMode<'a> {
    /// Initiates a new transaction that is committed after operations are executed.
    CreateNew,
    /// Utilizes an already active transaction for operations.
    UseExisting(&'a redb::WriteTransaction),
}
pub struct RedbDatabase {
    pub(crate) db: Arc<Database>,
    pub(crate) log_db: Arc<LogDatabase>,
    #[cfg(feature = "query")]
    accepted_rpy: Arc<AcceptedKsn>,
}

impl RedbDatabase {
    pub fn new(db_path: &Path) -> Result<Self, RedbError> {
        let db = Arc::new(Database::create(db_path)?);
        let log_db = Arc::new(LogDatabase::new(db.clone())?);
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(KELS)?;
            write_txn.open_table(KEY_STATES)?;
        }
        write_txn.commit()?;
        Ok(Self {
            db: db.clone(),
            log_db,
            #[cfg(feature = "query")]
            accepted_rpy: Arc::new(AcceptedKsn::new(db.clone())?),
        })
    }
}

impl EventDatabase for RedbDatabase {
    type Error = RedbError;
    type LogDatabaseType = LogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        let txn_mode = WriteTxnMode::UseExisting(&write_txn);

        self.update_key_state(&txn_mode, &signed_event.event_message)?;
        self.log_db.log_event(&txn_mode, &signed_event)?;

        self.save_to_kel(&txn_mode, &signed_event.event_message)?;

        write_txn.commit()?;
        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let digest = receipt.body.receipted_event_digest;
        let transferable = Transferable::Seal(receipt.validator_seal, receipt.signatures);
        self.log_db.insert_trans_receipt(&digest, &[transferable])
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let receipted_event_digest = receipt.body.receipted_event_digest;
        let receipts = receipt.signatures;
        self.log_db.insert_nontrans_receipt(
            &WriteTxnMode::CreateNew,
            &receipted_event_digest,
            &receipts,
        )
    }

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_table(KEY_STATES).unwrap();
        let key = id.to_str();
        if let Some(key_state) = table.get(key.as_str()).unwrap() {
            let bytes = key_state.value();
            Some(rkyv_adapter::deserialize_identifier_state(bytes).unwrap())
        } else {
            None
        }
    }

    fn get_kel_finalized_events(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = super::timestamped::TimestampedSignedEventMessage>>
    {
        let out = match params {
            QueryParameters::BySn { id, sn } => self
                .get_kel(&id, sn, 1)
                .map(|el| Some(el.into_iter()))
                .unwrap(),
            QueryParameters::Range { id, start, limit } => self
                .get_kel(&id, start, limit)
                .map(|el| Some(el.into_iter()))
                .unwrap(),
            QueryParameters::All { id } => self.get_full_kel(id).map(|kel| kel.into_iter()),
        };
        out
    }

    fn get_receipts_t(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>> {
        match params {
            QueryParameters::BySn { id, sn } => {
                if let Ok(Some(said)) = self.get_event_digest(&id, sn) {
                    let receipts = self.log_db.get_trans_receipts(&said).ok()?;
                    Some(receipts.collect::<Vec<_>>().into_iter())
                } else {
                    None
                }
            }
            QueryParameters::Range {
                id: _,
                start: _,
                limit: _,
            } => todo!(),
            QueryParameters::All { id: _ } => todo!(),
        }
    }

    fn get_receipts_nt(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        match params {
            QueryParameters::BySn { id, sn } => self
                .get_nontrans_receipts_range(&id.to_str(), sn, 1)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::Range { id, start, limit } => self
                .get_nontrans_receipts_range(&id.to_str(), start, limit)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::All { id } => self
                .get_nontrans_receipts_range(&id.to_str(), 0, u64::MAX)
                .ok()
                .map(|e| e.into_iter()),
        }
    }

    fn accept_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), RedbError> {
        let txn_mode = WriteTxnMode::CreateNew;
        self.save_to_kel(&txn_mode, event)?;
        self.update_key_state(&txn_mode, event)?;

        Ok(())
    }

    #[cfg(feature = "query")]
    fn save_reply(&self, reply: SignedReply) -> Result<(), Self::Error> {
        self.accepted_rpy.insert(reply)
    }

    #[cfg(feature = "query")]
    fn get_reply(&self, id: &IdentifierPrefix, from_who: &IdentifierPrefix) -> Option<SignedReply> {
        self.accepted_rpy.get(id, from_who).unwrap()
    }
}

impl RedbDatabase {
    /// Saves KEL event of given identifier. Key is identifier and sn of event, and value is event digest.
    fn save_to_kel(
        &self,
        txn_mode: &WriteTxnMode,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;

        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_table(KELS)?;
            let id = event.data.prefix.to_str();
            let sn = event.data.sn;
            let serialized_said = rkyv_adapter::serialize_said(&digest)?;
            table.insert((id.as_str(), sn), &serialized_said.as_slice())?;
            Ok(())
        })
    }

    fn update_key_state(
        &self,
        txn_mode: &WriteTxnMode,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), RedbError> {
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_table(KEY_STATES)?;
            let key = event.data.prefix.to_str();

            let key_state = if let Some(key_state) = table.get(key.as_str())? {
                let bytes = key_state.value();
                rkyv_adapter::deserialize_identifier_state(bytes).unwrap()
            } else {
                IdentifierState::default()
            };

            let key_state = key_state
                .apply(event)
                .map_err(|_e| RedbError::AlreadySaved(event.digest().unwrap()))?;
            let value = rkyv::to_bytes::<rkyv::rancor::Error>(&key_state)?;
            table.insert(key.as_str(), value.as_ref())?;

            Ok(())
        })
    }

    fn get_event_digest(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<SelfAddressingIdentifier>, RedbError> {
        Ok({
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(KELS)?;
            table
                .get((identifier.to_str().as_str(), sn))?
                .map(|value| -> Result<SelfAddressingIdentifier, RedbError> {
                    let digest: SelfAddressingIdentifier =
                        rkyv_adapter::deserialize_said(value.value())?;
                    Ok(digest)
                })
                .transpose()?
        })
    }

    fn get_nontrans_receipts_range(
        &self,
        id: &str,
        start: u64,
        limit: u64,
    ) -> Result<Vec<SignedNontransferableReceipt>, RedbError> {
        let corresponding_digests = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(KELS)?;
            table.range((id, start)..(id, start + limit))
        }?;
        let out = corresponding_digests
            .map(|digest| match digest {
                Ok((_, value)) => {
                    let said = rkyv_adapter::deserialize_said(value.value()).unwrap();
                    let nontrans = self
                        .log_db
                        .get_nontrans_couplets_by_key(value.value())
                        .unwrap()
                        .map(|vec| vec.collect())
                        .unwrap_or_default();
                    let identifier = id.parse().unwrap();
                    let rct = Receipt::new(SerializationFormats::JSON, said, identifier, start);
                    SignedNontransferableReceipt {
                        body: rct,
                        signatures: nontrans,
                    }
                }
                Err(_) => todo!(),
            })
            .collect();
        Ok(out)
    }

    fn get_all_nontrans_receipts_couplets(
        &self,
        id: &str,
    ) -> Result<Box<dyn DoubleEndedIterator<Item = Nontransferable>>, RedbError> {
        let corresponding_digests = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(KELS)?;
            table.range((id, 0)..(id, u64::MAX))
        }?;
        let out = corresponding_digests
            .map(|digest| match digest {
                Ok((_, value)) => self
                    .log_db
                    .get_nontrans_couplets_by_key(value.value())
                    .unwrap()
                    .unwrap(),
                Err(_) => todo!(),
            })
            .flatten();

        Ok(Box::new(out.collect::<Vec<_>>().into_iter()))
    }

    fn get_kel<'a>(
        &'a self,
        id: &IdentifierPrefix,
        from: u64,
        limit: u64,
    ) -> Result<Vec<timestamped::Timestamped<SignedEventMessage>>, RedbError> {
        let digests = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(KELS)?;
            table.range((id.to_str().as_str(), from)..(id.to_str().as_str(), from + limit))?
        };

        digests
            .filter_map(|entry| {
                let (_, value) = entry.unwrap();
                self.log_db
                    .get_signed_event_by_serialized_key(value.value())
                    .transpose()
            })
            .collect()
    }

    fn get_full_kel<'a>(
        &'a self,
        id: &IdentifierPrefix,
    ) -> Option<Vec<timestamped::Timestamped<SignedEventMessage>>> {
        let digests = {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(KELS);
            match table {
                Ok(table) => table
                    .range((id.to_str().as_str(), 0)..(id.to_str().as_str(), u64::MAX))
                    .unwrap(),
                Err(_e) => return None,
            }
        };

        let kel = digests
            .map(|entry| {
                let (_key, value) = entry.unwrap();
                self.log_db
                    .get_signed_event_by_serialized_key(value.value())
                    .unwrap()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        if kel.is_empty() {
            None
        } else {
            Some(kel)
        }
    }
}

/// Executes a given operation within a transaction context.
/// Uses an existing transaction if `WriteTxnMode::UseExisting` is specified.
/// Creates and commits a new transaction if `WriteTxnMode::CreateNew` is specified.
pub fn execute_in_transaction<F>(
    db: Arc<Database>,
    txn_mode: &WriteTxnMode,
    operation: F,
) -> Result<(), RedbError>
where
    F: FnOnce(&redb::WriteTransaction) -> Result<(), RedbError>,
{
    match *txn_mode {
        WriteTxnMode::UseExisting(existing_txn) => {
            operation(existing_txn)?;
        }
        WriteTxnMode::CreateNew => {
            let txn = db.begin_write()?;
            operation(&txn)?;
            txn.commit()?;
        }
    };

    Ok(())
}

#[test]
fn test_retrieve_kel() -> Result<(), RedbError> {
    use crate::actor::parse_event_stream;
    use crate::event_message::signed_event_message::{Message, Notice};
    use crate::event_message::EventTypeTag;
    use tempfile::NamedTempFile;
    // Create test db path.
    let file_path = NamedTempFile::new().unwrap();

    let db = RedbDatabase::new(file_path.path()).unwrap();

    let icp_raw: &[u8] = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let rot_raw: &[u8] = br#"{"v":"KERI10JSON00021c_","t":"rot","d":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","p":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","kt":"2","k":["DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE","DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV","DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"],"nt":"2","n":["EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","EATiZAHl0kzKID6faaQP2O7zB3Hj7eH3bE-vgKVAtsyU","EG6e7dJhh78ZqeIZ-eMbe-OB3TwFMPmrSsh9k75XIjLP"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAqV6xpsAAEB_FJP5UdYO5qiJphz8cqXbTjB9SRy8V0wIim-lgafF4o-b7TW0spZtzx2RXUfZLQQCIKZsw99k8AABBP8nfF3t6bf4z7eNoBgUJR-hdhw7wnlljMZkeY5j2KFRI_s8wqtcOFx1A913xarGJlO6UfrqFWo53e9zcD8egIACB8DKLMZcCGICuk98RCEVuS0GsqVngi1d-7gAX0jid42qUcR3aiYDMp2wJhqJn-iHJVvtB-LK7TRTggBtMDjuwB"#;
    let ixn_raw: &[u8] = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"2","p":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","a":[]}-AADAABgep0kbpgl91vvcXziJ7tHY1WVTAcUJyYCBNqTcNuK9AfzLHfKHhJeSC67wFRU845qjLSAC-XwWaqWgyAgw_8MABD5wTnqqJcnLWMA7NZ1vLOTzDspInJrly7O4Kt6Jwzue9z2TXkDXi1jr69JeKbzUQ6c2Ka1qPXAst0JzrOiyuAPACAcLHnOz1Owtgq8mcR_-PpAr91zOTK_Zj9r0V-9P47vzGsYwAxcVshclfhCMhu73aZuZbvQhy9Rxcj-qRz96cIL"#;
    let second_icp_raw = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"0","kt":"1","k":["DIwDbi2Sr1kLZFpsX0Od6Y8ariGVLLjZXxBC5bXEI85e"],"nt":"1","n":["ELhmgZ5JFc-ACs9TJxHMxtcKzQxKXLhlAmUT_sKf1-l7"],"bt":"0","b":["DM73ulUG2_DJyA27DfxBXT5SJ5U3A3c2oeG8Z4bUOgyL"],"c":[],"a":[]}-AABAAAPGpCUdR6EfVWROUjpuTsxg5BIcMnfi7PDciv8VuY9NqZ0ioRoaHxMZue_5ALys86sX4aQzKqm_bID3ZBwlMUP"#;

    let first_id: IdentifierPrefix = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"
        .parse()
        .unwrap();

    for event in [icp_raw, rot_raw, ixn_raw, second_icp_raw] {
        let evs = parse_event_stream(event).unwrap();
        let ev = evs.first().unwrap();
        match ev {
            Message::Notice(Notice::Event(event)) => {
                db.add_kel_finalized_event(event.clone(), &event.event_message.data.get_prefix())
                    .unwrap();
            }
            _ => unreachable!(),
        }
    }

    let first_event = &db.get_kel(&first_id, 0, 1)?[0].signed_event_message;

    let expected_event = &icp_raw[..487]; // icp event without signatures
    assert_eq!(first_event.event_message.encode().unwrap(), expected_event);

    let sigs_from_db = &first_event.signatures;
    assert_eq!(sigs_from_db.len(), 3);

    // Retrieve KEL in range
    let mut part_of_kel_events = db.get_kel(&first_id, 1, 2)?.into_iter();

    let rot = part_of_kel_events.next().unwrap();
    assert_eq!(
        rot.signed_event_message.event_message.event_type,
        EventTypeTag::Rot
    );
    assert_eq!(
        rot.signed_event_message.event_message.digest,
        Some(
            "EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz"
                .parse::<SelfAddressingIdentifier>()
                .unwrap()
                .into()
        )
    );
    assert_eq!(rot.signed_event_message.signatures.len(), 3);

    let ixn = part_of_kel_events.next().unwrap();
    assert_eq!(
        ixn.signed_event_message.event_message.event_type,
        EventTypeTag::Ixn
    );
    assert_eq!(
        ixn.signed_event_message.event_message.digest,
        Some(
            "EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz"
                .parse::<SelfAddressingIdentifier>()
                .unwrap()
                .into()
        )
    );
    assert_eq!(ixn.signed_event_message.signatures.len(), 3);

    assert_eq!(part_of_kel_events.next(), None);

    // Retrieve KEL in range
    let mut part_of_kel_events = db.get_kel(&first_id, 0, 2)?.into_iter();
    let icp = part_of_kel_events.next().unwrap();
    assert_eq!(
        icp.signed_event_message.event_message.event_type,
        EventTypeTag::Icp
    );
    assert_eq!(
        icp.signed_event_message.event_message.digest,
        Some(
            "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"
                .parse::<SelfAddressingIdentifier>()
                .unwrap()
                .into()
        )
    );
    assert_eq!(icp.signed_event_message.signatures.len(), 3);

    let rot = part_of_kel_events.next().unwrap();
    assert_eq!(
        rot.signed_event_message.event_message.event_type,
        EventTypeTag::Rot
    );
    assert_eq!(
        rot.signed_event_message.event_message.digest,
        Some(
            "EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz"
                .parse::<SelfAddressingIdentifier>()
                .unwrap()
                .into()
        )
    );
    assert_eq!(rot.signed_event_message.signatures.len(), 3);

    assert_eq!(part_of_kel_events.next(), None);

    let key_state = db.get_key_state(&first_id).unwrap();
    assert_eq!(key_state.sn, 2);
    assert_eq!(
        key_state.last_event_digest,
        "EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz"
            .parse::<SelfAddressingIdentifier>()
            .unwrap()
            .into()
    );
    Ok(())
}
