pub(crate) mod rkyv_adapter;

/// Kel storage. (identifier, sn) -> event digest
/// The `KELS` table links an identifier and sequence number to the digest of an event,
/// referencing the actual event stored in the `EVENTS` table.
const KELS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kels");

/// Events store. (event digest) -> key event
/// The `EVENTS` table directly stores the event data, which other tables reference
/// by its digest.
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");

/// Signatures storage. (identifier, sn) -> signature
/// The `SIGS` table links an identifier and sequence number to one or more
/// signatures.
const SIGS: MultimapTableDefinition<(&str, u64), &[u8]> =
    MultimapTableDefinition::new("signatures");

/// Nontransferable receipts storage. (identifier, sn) -> signature couplet (one or more)
const NONTRANS_RCTS: MultimapTableDefinition<(&str, u64), &[u8]> =
    MultimapTableDefinition::new("nontrans_receipts");

/// Nontransferable receipts storage. (identifier, sn) -> transferable receipt (one or more)
const TRANS_RCTS: MultimapTableDefinition<(&str, u64), &[u8]> =
    MultimapTableDefinition::new("trans_receipts");

use std::{path::Path, u64};

use redb::{Database, MultimapTableDefinition, TableDefinition};
use rkyv::{
    api::high::HighSerializer, rancor::Failure, ser::allocator::ArenaHandle, util::AlignedVec,
};
use rkyv_adapter::deserialize_indexed_signatures;
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
    prefix::{IdentifierPrefix, IndexedSignature},
};
use cesrox::primitives::CesrPrimitive;

use self::timestamped::TimestampedSignedEventMessage;

use super::{timestamped, EventDatabase, QueryParameters};

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
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Can't parse said in key")]
    UnparsableSaid,
    #[error("Can't parse index in key")]
    UnparsableIndex,
}

pub struct RedbDatabase {
    db: Database,
}

impl RedbDatabase {
    pub fn new(db_path: &Path) -> Result<Self, RedbError> {
        let db = Database::create(db_path)?;
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(EVENTS)?;
            write_txn.open_table(KELS)?;
            write_txn.open_multimap_table(SIGS)?;
            write_txn.open_multimap_table(TRANS_RCTS)?;
            write_txn.open_multimap_table(NONTRANS_RCTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }
}

impl EventDatabase for RedbDatabase {
    type Error = RedbError;
    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let event = &signed_event.event_message;
        self.insert_key_event(event)?;
        let id = &event.data.prefix;
        let sn = event.data.sn;

        self.insert_indexed_signatures(&id, sn, &signed_event.signatures)?;
        if let Some(wits) = signed_event.witness_receipts {
            self.insert_nontrans_receipt(&id.to_str(), sn, &wits)?;
        };
        self.save_to_kel(event)?;
        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let sn = receipt.body.sn;
        let id = receipt.body.prefix;
        let transferable = Transferable::Seal(receipt.validator_seal, receipt.signatures);
        self.insert_trans_receipt(&id.to_str(), sn, &[transferable])
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let sn = receipt.body.sn;
        let id = receipt.body.prefix;
        let receipts = receipt.signatures;
        self.insert_nontrans_receipt(&id.to_str(), sn, &receipts)
    }

    fn get_kel_finalized_events(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = super::timestamped::TimestampedSignedEventMessage>>
    {
        match params {
            QueryParameters::BySn { id, sn } => Some(self.get_kel(&id, sn, 1).into_iter()),
            QueryParameters::Range { id, start, limit } => {
                Some(self.get_kel(&id, start, limit).into_iter())
            }
            QueryParameters::All { id } => self.get_full_kel(id).map(|kel| kel.into_iter()),
        }
    }

    fn get_receipts_t(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>> {
        match params {
            QueryParameters::BySn { id, sn } => self.get_trans_receipts(&id.to_str(), sn).ok(),
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
}

impl RedbDatabase {
    /// Saves provided event into key event table. Key is it's digest and value is event.
    fn insert_key_event(&self, event: &KeriEvent<KeyEvent>) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;
        let value = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(EVENTS)?;
            let key = rkyv_adapter::serialize_said(&digest)?;
            table.insert(key.as_slice(), &value.as_ref())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    /// Saves KEL event of given identifier. Key is identifier and sn of event, and value is event digest.
    fn save_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(KELS)?;
            let id = event.data.prefix.to_str();
            let sn = event.data.sn;
            let serialized_said = rkyv_adapter::serialize_said(&digest)?;
            table.insert((id.as_str(), sn), &serialized_said.as_slice())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    fn insert_with_sn_key<
        V: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>,
    >(
        &self,
        table: MultimapTableDefinition<(&str, u64), &[u8]>,
        id: &str,
        sn: u64,
        values: &[V],
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_multimap_table(table)?;

            for value in values {
                let sig = rkyv::to_bytes(value)?;
                table.insert((id, sn), sig.as_slice())?;
            }
        }
        write_txn.commit()?;

        Ok(())
    }

    fn insert_nontrans_receipt(
        &self,
        id: &str,
        sn: u64,
        nontrans: &[Nontransferable],
    ) -> Result<(), RedbError> {
        self.insert_with_sn_key(NONTRANS_RCTS, id, sn, nontrans)
    }

    fn insert_trans_receipt(
        &self,
        id: &str,
        sn: u64,
        trans: &[Transferable],
    ) -> Result<(), RedbError> {
        self.insert_with_sn_key(TRANS_RCTS, id, sn, trans)
    }

    fn insert_indexed_signatures(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        signatures: &[IndexedSignature],
    ) -> Result<(), RedbError> {
        self.insert_with_sn_key(SIGS, &identifier.to_str(), sn, signatures)
    }

    fn get_nontrans_couplets(
        &self,
        id: &str,
        sn: u64,
    ) -> Result<impl Iterator<Item = Nontransferable>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(NONTRANS_RCTS)?;
            table.get((id, sn))
        }?;
        let nontrans = from_db_iterator
            .map(|sig| match sig {
                Ok(sig) => Ok(rkyv_adapter::deserialize_nontransferable(sig.value()).unwrap()),
                Err(e) => Err(RedbError::from(e)),
            })
            .collect::<Result<Vec<_>, _>>();
        nontrans.map(|el| el.into_iter())
    }

    fn get_nontrans_couplets_by_key(
        &self,
        key: (&str, u64),
    ) -> Result<impl Iterator<Item = Nontransferable>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(NONTRANS_RCTS)?;
            table.get(key)
        }?;
        let nontrans = from_db_iterator
            .map(|sig| match sig {
                Ok(sig) => Ok(rkyv_adapter::deserialize_nontransferable(sig.value()).unwrap()),
                Err(e) => Err(RedbError::from(e)),
            })
            .collect::<Result<Vec<_>, _>>();
        nontrans.map(|el| el.into_iter())
    }


    fn get_nontrans_receipts_range(
        &self,
        id: &str,
        start: u64,
        limit: u64,
    ) -> Result<Vec<SignedNontransferableReceipt>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(NONTRANS_RCTS)?;
            table.range((id, start)..(id, start + limit))
        }?;
        let out: Vec<SignedNontransferableReceipt> = from_db_iterator
            .map(|sig| match sig {
                Ok((key, value)) => {
                    let (identifier, sn) = key.value();
                    let id = identifier.parse().unwrap();
                    let digest = self.get_event_digest(&id, sn).unwrap();
                    let nontrans = value
                        .map(|value| match value {
                            Ok(element) => {
                                rkyv_adapter::deserialize_nontransferable(element.value()).unwrap()
                            }
                            Err(_) => todo!(),
                        })
                        .collect::<Vec<_>>();
                    let rct = Receipt::new(SerializationFormats::JSON, digest.unwrap(), id, sn);
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
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(NONTRANS_RCTS)?;
            table.range((id, 0)..(id, u64::MAX))
        }?;
        let out = from_db_iterator
            .map(|sig| match sig {
                Ok((_key, value)) => value.map(|value| match value {
                    Ok(element) => {
                        rkyv_adapter::deserialize_nontransferable(element.value()).unwrap()
                    }
                    Err(_) => todo!(),
                }),
                Err(_) => todo!(),
            })
            .flatten();
        Ok(Box::new(out))
    }

    fn get_trans_receipts(
        &self,
        id: &str,
        sn: u64,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(TRANS_RCTS)?;
            table.get((id, sn))
        }?;
        Ok(from_db_iterator.map(|sig| match sig {
            Ok(sig) => rkyv_adapter::deserialize_transferable(sig.value()).unwrap(),
            Err(_) => todo!(),
        }))
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

    fn get_event_by_digest(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;

        let key = rkyv_adapter::serialize_said(&said).unwrap();
        if let Some(event) = table.get(key.as_slice())? {
            let bytes = event.value().to_vec();
            let deserialized: KeriEvent<KeyEvent> = rkyv::from_bytes::<_, Failure>(&bytes).unwrap();
            Ok(Some(deserialized))
        } else {
            Ok(None)
        }
    }

    fn get_event_by_serialized_key(
        &self,
        said_arch: &[u8],
    ) -> Result<Option<KeriEvent<KeyEvent>>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;

        if let Some(event) = table.get(said_arch)? {
            let bytes = event.value().to_vec();
            let deser: KeriEvent<KeyEvent> = rkyv::from_bytes::<_, Failure>(&bytes).unwrap();
            Ok(Some(deser))
        } else {
            Ok(None)
        }
    }

    fn get_signatures(
        &self,
        key: (&str, u64),
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table: redb::ReadOnlyMultimapTable<(&str, u64), &[u8]> =
                read_txn.open_multimap_table(SIGS)?;
            table.get(key)
        }?;
        Ok(Some(from_db_iterator.map(|sig| match sig {
            Ok(sig) => deserialize_indexed_signatures(sig.value()).unwrap(),
            Err(_) => todo!(),
        })))
    }

    fn get_kel<'a>(
        &'a self,
        id: &IdentifierPrefix,
        from: u64,
        limit: u64,
    ) -> Vec<timestamped::Timestamped<SignedEventMessage>> {
        let digests = {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(KELS).unwrap();
            table
                .range((id.to_str().as_str(), from)..(id.to_str().as_str(), from + limit))
                .unwrap()
        };

        digests
            .map(|entry| {
                let (key, value) = entry.unwrap();
                let signatures = self.get_signatures(key.value()).unwrap().unwrap().collect();

                let event = self
                    .get_event_by_serialized_key(&value.value())
                    .unwrap()
                    .unwrap();
                TimestampedSignedEventMessage::new(SignedEventMessage::new(
                    &event, signatures, None, None,
                ))
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

        Some(
            digests
                .map(|entry| {
                    let (key, value) = entry.unwrap();
                    let signatures = self.get_signatures(key.value()).unwrap().unwrap().collect();
                    let receipts = self.get_nontrans_couplets_by_key(key.value()).unwrap().collect();

                    let event = self
                        .get_event_by_serialized_key(value.value())
                        .unwrap()
                        .unwrap();
                    TimestampedSignedEventMessage::new(SignedEventMessage::new(
                        &event, signatures, Some(receipts), None,
                    ))
                })
                .collect(),
        )
    }
}

#[test]
fn test_retrieve_kel() {
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
    let second_id: IdentifierPrefix = "EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf"
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

    // Find event by digest
    let ev_digest: SelfAddressingIdentifier = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"
        .parse()
        .unwrap();
    let events = db.get_event_by_digest(&ev_digest).unwrap().unwrap();
    let expected_event = &icp_raw[..487]; // icp event without signatures
    assert_eq!(events.encode().unwrap(), expected_event);

    let sigs_from_db = db.get_signatures((&first_id.to_str(), 0)).unwrap().unwrap();
    assert_eq!(sigs_from_db.count(), 3);

    // Warning: order of retrieved signatures isn't the same as insertion order
    let sigs_from_db = db
        .get_signatures((&second_id.to_str(), 0))
        .unwrap()
        .unwrap();
    assert_eq!(sigs_from_db.count(), 1);

    // Retrieve KEL in range
    let mut part_of_kel_events = db.get_kel(&first_id, 1, 2).into_iter();

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
    let mut part_of_kel_events = db.get_kel(&first_id, 0, 2).into_iter();
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
}

#[test]
fn test_retrieve_receipts() {
    use crate::actor::parse_event_stream;
    use crate::event_message::signed_event_message::{Message, Notice};
    use tempfile::NamedTempFile;
    // Create test db path.
    let file_path = NamedTempFile::new().unwrap();

    let db = RedbDatabase::new(file_path.path()).unwrap();

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;

    let receipt1_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"1"}-CABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;
    let receipt1_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"1"}-CABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;

    let first_id: IdentifierPrefix = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
        .parse()
        .unwrap();

    for event in [receipt0_0, receipt0_1, receipt1_0, receipt1_1] {
        let evs = parse_event_stream(event).unwrap();
        let ev = evs.first().unwrap();
        match ev {
            Message::Notice(Notice::NontransferableRct(rct)) => {
                db.add_receipt_nt(rct.clone(), &first_id).unwrap();
            }
            _ => unreachable!(),
        }
    }

    let retrived_rcts = db.get_nontrans_couplets(&first_id.to_str(), 0).unwrap();
    assert_eq!(retrived_rcts.count(), 2);

    let all_retrived_rcts = db
        .get_all_nontrans_receipts_couplets(&first_id.to_str())
        .unwrap();
    assert_eq!(all_retrived_rcts.count(), 4);
}
