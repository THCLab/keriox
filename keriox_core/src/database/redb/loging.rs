/// Events store. (event digest) -> key event
/// The `EVENTS` table directly stores the event data, which other tables reference
/// by its digest.
const EVENTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("events");

/// Signatures storage. (event digest) -> signature
/// The `SIGS` table links event digest to one or more
/// signatures.
const SIGS: MultimapTableDefinition<&[u8], &[u8]> = MultimapTableDefinition::new("signatures");

/// Nontransferable receipts storage. (event digest) -> signature couplet (one or more)
const NONTRANS_RCTS: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("nontrans_receipts");

/// Nontransferable receipts storage. (event digest) -> transferable receipt (one or more)
const TRANS_RCTS: MultimapTableDefinition<&[u8], &[u8]> =
    MultimapTableDefinition::new("trans_receipts");

/// Delegating Event Seals (event digest) -> seal
const SEALS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("seals");

use std::sync::Arc;

use redb::{Database, MultimapTableDefinition, TableDefinition};
use rkyv::{
    api::high::HighSerializer,
    rancor::{self, Failure},
    ser::allocator::ArenaHandle,
    util::AlignedVec,
};
use said::SelfAddressingIdentifier;

use crate::{
    database::timestamped::TimestampedSignedEventMessage,
    event::{sections::seal::SourceSeal, KeyEvent},
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::{SignedEventMessage, SignedNontransferableReceipt},
    },
    prefix::IndexedSignature,
};

use super::{
    execute_in_transaction,
    rkyv_adapter::{self, deserialize_indexed_signatures, deserialize_source_seal},
    RedbError, WriteTxnMode,
};

/// Stores all incoming signed events and enables retrieval by event digest.  
/// Events are split into separate tables for events, signatures, and receipts,  
/// with the digest serving as the key in each table.
pub(crate) struct LogDatabase {
    db: Arc<Database>,
}

impl LogDatabase {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(EVENTS)?;
            write_txn.open_multimap_table(SIGS)?;
            write_txn.open_multimap_table(TRANS_RCTS)?;
            write_txn.open_multimap_table(NONTRANS_RCTS)?;
            write_txn.open_table(SEALS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    pub fn log_event(
        &self,
        txn_mode: &WriteTxnMode,
        signed_event: &SignedEventMessage,
    ) -> Result<(), RedbError> {
        self.insert_key_event(&txn_mode, &signed_event.event_message)?;
        let digest = signed_event
            .event_message
            .digest()
            .map_err(|_e| RedbError::MissingDigest)?;

        self.insert_indexed_signatures(&txn_mode, &digest, &signed_event.signatures)?;
        if let Some(wits) = &signed_event.witness_receipts {
            self.insert_nontrans_receipt(&txn_mode, &digest, &wits)?;
        };

        if let Some(delegator_seal) = &signed_event.delegator_seal {
            self.insert_source_seal(&txn_mode, &digest, delegator_seal)?;
        }
        Ok(())
    }

    pub fn log_receipt(
        &self,
        txn_mode: &WriteTxnMode,
        signed_receipt: &SignedNontransferableReceipt,
    ) -> Result<(), RedbError> {
        let digest = &signed_receipt.body.receipted_event_digest;

        self.insert_nontrans_receipt(&txn_mode, digest, &signed_receipt.signatures)?;
        Ok(())
    }

    // pub fn remove_receipt(
    //     &self,
    //     txn_mode: &WriteTxnMode,
    //     signed_receipt: &SignedNontransferableReceipt,
    // ) -> Result<(), RedbError> {
    //     let digest = &signed_receipt.body.receipted_event_digest;

    //     // self.db.remove_receipt(txn_mode, signed_receipt)
    //     Ok(())
    // }

    pub fn get_signed_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, RedbError> {
        let key = rkyv_adapter::serialize_said(said)?;
        self.get_signed_event_by_serialized_key(key.as_slice())
    }

    pub fn get_event(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, RedbError> {
        let key = rkyv_adapter::serialize_said(&said).unwrap();
        self.get_event_by_serialized_key(&key.as_slice())
    }

    pub fn get_signatures(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, RedbError> {
        let key = rkyv_adapter::serialize_said(&said).unwrap();
        self.get_signatures_by_serialized_key(&key.as_slice())
    }

    pub fn get_nontrans_couplets(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, RedbError> {
        let said = rkyv_adapter::serialize_said(said)?;
        self.get_nontrans_couplets_by_key(&said)
    }

    pub fn get_trans_receipts(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, RedbError> {
        let key = rkyv_adapter::serialize_said(said)?;
        self.get_trans_receipts_by_serialized_key(key.as_slice())
    }
}

impl LogDatabase {
    pub(super) fn get_signed_event_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<Option<TimestampedSignedEventMessage>, RedbError> {
        let signatures = self
            .get_signatures_by_serialized_key(&key)
            .unwrap()
            .unwrap()
            .collect();
        let source_seal = self.get_delegator_seal_by_serialized_key(key)?;

        let event = self.get_event_by_serialized_key(&key)?;
        Ok(event.map(|ev| {
            let receipts = self
                .get_nontrans_couplets_by_key(key)
                .unwrap()
                .map(|vec| vec.collect());
            TimestampedSignedEventMessage::new(SignedEventMessage::new(
                &ev,
                signatures,
                receipts,
                source_seal,
            ))
        }))
    }

    /// Saves provided event into key event table. Key is it's digest and value is event.
    fn insert_key_event(
        &self,
        txn_mode: &WriteTxnMode,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;
        let value = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;

        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_table(EVENTS)?;
            let key = rkyv_adapter::serialize_said(&digest)?;
            table.insert(key.as_slice(), &value.as_ref())?;
            Ok(())
        })
    }

    fn insert_with_digest_key<
        V: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>,
    >(
        &self,
        txn_mode: &WriteTxnMode,
        table: MultimapTableDefinition<&[u8], &[u8]>,
        said: &SelfAddressingIdentifier,
        values: &[V],
    ) -> Result<(), RedbError> {
        let serialized_said = rkyv_adapter::serialize_said(said)?;
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_multimap_table(table)?;

            for value in values {
                let sig = rkyv::to_bytes(value)?;
                table.insert(serialized_said.as_slice(), sig.as_slice())?;
            }
            Ok(())
        })
    }

    pub(super) fn insert_nontrans_receipt(
        &self,
        txn_mode: &WriteTxnMode,
        said: &SelfAddressingIdentifier,
        nontrans: &[Nontransferable],
    ) -> Result<(), RedbError> {
        self.insert_with_digest_key(txn_mode, NONTRANS_RCTS, said, nontrans)
    }

    pub(super) fn insert_source_seal(
        &self,
        txn_mode: &WriteTxnMode,
        said: &SelfAddressingIdentifier,
        seal: &SourceSeal,
    ) -> Result<(), RedbError> {
        let serialized_said = rkyv_adapter::serialize_said(said)?;
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_table(SEALS)?;

            let seal = rkyv::to_bytes::<rkyv::rancor::Error>(seal)?;
            table.insert(serialized_said.as_slice(), seal.as_ref())?;
            Ok(())
        })
    }

    pub(super) fn remove_nontrans_receipt(
        &self,
        txn_mode: &WriteTxnMode,
        said: &SelfAddressingIdentifier,
        nontrans: &[Nontransferable],
    ) -> Result<(), RedbError> {
        let serialized_said = rkyv_adapter::serialize_said(said)?;
        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_multimap_table(NONTRANS_RCTS)?;

            for value in nontrans {
                let value = rkyv::to_bytes::<rancor::Error>(value)?;
                table.remove(serialized_said.as_slice(), value.as_slice())?;
            }
            Ok(())
        })
    }

    pub(super) fn insert_trans_receipt(
        &self,
        said: &SelfAddressingIdentifier,
        trans: &[Transferable],
    ) -> Result<(), RedbError> {
        self.insert_with_digest_key(&WriteTxnMode::CreateNew, TRANS_RCTS, &said, trans)
    }

    pub(super) fn insert_indexed_signatures(
        &self,
        txn_mode: &WriteTxnMode,
        said: &SelfAddressingIdentifier,
        signatures: &[IndexedSignature],
    ) -> Result<(), RedbError> {
        self.insert_with_digest_key(txn_mode, SIGS, said, signatures)
    }

    pub(super) fn get_nontrans_couplets_by_key(
        &self,
        key: &[u8],
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, RedbError> {
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
        nontrans.map(|el| {
            if el.is_empty() {
                None
            } else {
                Some(el.into_iter())
            }
        })
    }

    fn get_trans_receipts_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_multimap_table(TRANS_RCTS)?;
            table.get(key)
        }?;
        Ok(from_db_iterator.map(|sig| match sig {
            Ok(sig) => rkyv_adapter::deserialize_transferable(sig.value()).unwrap(),
            Err(_) => todo!(),
        }))
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

    fn get_signatures_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, RedbError> {
        let from_db_iterator = {
            let read_txn = self.db.begin_read()?;
            let table: redb::ReadOnlyMultimapTable<&[u8], &[u8]> =
                read_txn.open_multimap_table(SIGS)?;
            table.get(key)
        }?;
        Ok(Some(from_db_iterator.map(|sig| match sig {
            Ok(sig) => deserialize_indexed_signatures(sig.value()).unwrap(),
            Err(_) => todo!(),
        })))
    }

    fn get_delegator_seal_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<Option<SourceSeal>, RedbError> {
        let maybe_seal = {
            let read_txn = self.db.begin_read()?;
            let table = read_txn.open_table(SEALS)?;
            table.get(key)
        }?;
        Ok(maybe_seal.map(|seal| deserialize_source_seal(seal.value()).unwrap()))
    }
}

#[test]
fn test_retrieve_by_digest() {
    use crate::actor::parse_event_stream;
    use crate::event_message::signed_event_message::{Message, Notice};
    use tempfile::NamedTempFile;
    // Create test db path.
    let file_path = NamedTempFile::new().unwrap();

    let db = Arc::new(Database::create(file_path.path()).unwrap());
    let log = LogDatabase::new(db.clone()).unwrap();
    // let db = RedbDatabase::new(file_path.path()).unwrap();

    let icp_raw: &[u8] = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let rot_raw: &[u8] = br#"{"v":"KERI10JSON00021c_","t":"rot","d":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","p":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","kt":"2","k":["DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE","DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV","DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"],"nt":"2","n":["EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","EATiZAHl0kzKID6faaQP2O7zB3Hj7eH3bE-vgKVAtsyU","EG6e7dJhh78ZqeIZ-eMbe-OB3TwFMPmrSsh9k75XIjLP"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAqV6xpsAAEB_FJP5UdYO5qiJphz8cqXbTjB9SRy8V0wIim-lgafF4o-b7TW0spZtzx2RXUfZLQQCIKZsw99k8AABBP8nfF3t6bf4z7eNoBgUJR-hdhw7wnlljMZkeY5j2KFRI_s8wqtcOFx1A913xarGJlO6UfrqFWo53e9zcD8egIACB8DKLMZcCGICuk98RCEVuS0GsqVngi1d-7gAX0jid42qUcR3aiYDMp2wJhqJn-iHJVvtB-LK7TRTggBtMDjuwB"#;
    let ixn_raw: &[u8] = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"2","p":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","a":[]}-AADAABgep0kbpgl91vvcXziJ7tHY1WVTAcUJyYCBNqTcNuK9AfzLHfKHhJeSC67wFRU845qjLSAC-XwWaqWgyAgw_8MABD5wTnqqJcnLWMA7NZ1vLOTzDspInJrly7O4Kt6Jwzue9z2TXkDXi1jr69JeKbzUQ6c2Ka1qPXAst0JzrOiyuAPACAcLHnOz1Owtgq8mcR_-PpAr91zOTK_Zj9r0V-9P47vzGsYwAxcVshclfhCMhu73aZuZbvQhy9Rxcj-qRz96cIL"#;
    let second_icp_raw = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","i":"EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf","s":"0","kt":"1","k":["DIwDbi2Sr1kLZFpsX0Od6Y8ariGVLLjZXxBC5bXEI85e"],"nt":"1","n":["ELhmgZ5JFc-ACs9TJxHMxtcKzQxKXLhlAmUT_sKf1-l7"],"bt":"0","b":["DM73ulUG2_DJyA27DfxBXT5SJ5U3A3c2oeG8Z4bUOgyL"],"c":[],"a":[]}-AABAAAPGpCUdR6EfVWROUjpuTsxg5BIcMnfi7PDciv8VuY9NqZ0ioRoaHxMZue_5ALys86sX4aQzKqm_bID3ZBwlMUP"#;

    for event in [icp_raw, rot_raw, ixn_raw, second_icp_raw] {
        let evs = parse_event_stream(event).unwrap();
        let ev = evs.first().unwrap();
        match ev {
            Message::Notice(Notice::Event(event)) => {
                log.log_event(&WriteTxnMode::CreateNew, event).unwrap();
            }
            _ => unreachable!(),
        }
    }

    // Find event by digest
    let ev_digest: SelfAddressingIdentifier = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"
        .parse()
        .unwrap();

    let event_from_db = log.get_event(&ev_digest).unwrap().unwrap();
    let expected_event = &icp_raw[..487]; // icp event without signatures
    assert_eq!(event_from_db.encode().unwrap(), expected_event);

    let sigs_from_db = log.get_signatures(&ev_digest).unwrap().unwrap();
    assert_eq!(sigs_from_db.count(), 3);

    // Find event by digest
    let ev_digest: SelfAddressingIdentifier = "EFb-WY7Ie1WPEgsioZz1CyzwnuCg-C9k2QCNpcUfM5Jf"
        .parse()
        .unwrap();
    // Warning: order of retrieved signatures isn't the same as insertion order
    let sigs_from_db = log.get_signatures(&ev_digest).unwrap().unwrap();
    assert_eq!(sigs_from_db.count(), 1);
}

#[test]
fn test_retrieve_receipts() {
    use crate::actor::parse_event_stream;
    use crate::database::EventDatabase;
    use crate::event_message::signed_event_message::{Message, Notice};
    use crate::prefix::IdentifierPrefix;
    use tempfile::NamedTempFile;
    // Create test db path.
    let file_path = NamedTempFile::new().unwrap();

    let db = super::RedbDatabase::new(file_path.path()).unwrap();

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;

    let receipt1_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EBgRuemKRwpDnemmrA9bbWyp0Ar4BHVv4ZjIv8mBGJxj","i":"EPNYUP688XxtHUfxeHlqxqSduMHmWrpjRzlUCKPtvB7t","s":"2"}-CABBDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP0BCjSM8pvkBQNcx3yN1fPMfaOqGllSBsYX9bijFWQV_d9PxJI1dvxt5lW4xAf9SGWb28Nzt3J0MOsO69aYMy0XMD"#;
    let receipt1_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EBgRuemKRwpDnemmrA9bbWyp0Ar4BHVv4ZjIv8mBGJxj","i":"EPNYUP688XxtHUfxeHlqxqSduMHmWrpjRzlUCKPtvB7t","s":"2"}-CABBJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC0BBRh0mufCacSimM85yV0kcFnx6U76XR5vibN4biUtzmrjl_s2yvVUDBu3vZvRwH-wy6FgU02WydaFmmeysG_pAN"#;

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

    let recipted_event_digest: SelfAddressingIdentifier =
        "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();
    let retrived_rcts = db
        .log_db
        .get_nontrans_couplets(&recipted_event_digest)
        .unwrap();
    assert_eq!(retrived_rcts.unwrap().count(), 2);

    let recipted_event_digest: SelfAddressingIdentifier =
        "EBgRuemKRwpDnemmrA9bbWyp0Ar4BHVv4ZjIv8mBGJxj"
            .parse()
            .unwrap();
    let retrived_rcts = db
        .log_db
        .get_nontrans_couplets(&recipted_event_digest)
        .unwrap();
    assert_eq!(retrived_rcts.unwrap().count(), 2);
}
