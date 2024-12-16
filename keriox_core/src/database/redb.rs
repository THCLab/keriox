/// Kel storage. (identifier, sn) -> event digest
const KELS: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kels");
/// Events store. (event digest) -> serialized event
const EVENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("events");
// Nontransferable receipts storage. (identifier, sn, witness identifier) -> signature couplet
const RCTS: MultimapTableDefinition<&str, u64> = MultimapTableDefinition::new("rcts");
/// Signatures storage. (event digest, signature index) -> serialized event
const SIGS: MultimapTableDefinition<(&str, u64), &[u8]> = MultimapTableDefinition::new("sigs");

use std::path::Path;

use redb::{Database, MultimapTableDefinition, TableDefinition};
use said::SelfAddressingIdentifier;

use crate::{
    actor::prelude::Message,
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signed_event_message::{
            Notice, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
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
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("Can't parse said in key")]
    UnparsableSaid,
    #[error("Can't parse index in key")]
    UnparsableIndex,
}

struct RedbDatabase {
    db: Database,
}

impl RedbDatabase {
    pub fn new(db_path: &Path) -> Result<Self, RedbError> {
        let db = Database::create(db_path)?;
        Ok(Self { db })
    }
}

impl EventDatabase for RedbDatabase {
    type Error = RedbError;
    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        let event = &signed_event.event_message;
        self.insert_key_event(event)?;
        let id = &event.data.prefix;
        let sn = event.data.sn;
        for signature in &signed_event.signatures {
            self.insert_indexed_signatures(&id, sn, signature)?;
        }
        self.save_to_kel(event)?;
        Ok(())
    }

    fn add_receipt_t(
        &self,
        receipt: SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        todo!()
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), RedbError> {
        todo!()
    }

    fn get_kel_finalized_events(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = super::timestamped::TimestampedSignedEventMessage>>
    {
        match params {
            QueryParameters::BySn { id, sn } => todo!(),
            QueryParameters::ByDigest { digest } => todo!(),
            QueryParameters::Range { id, start, limit } => {
                Some(self.get_kel(&id, start, limit).into_iter())
            }
            QueryParameters::All { id } => todo!(),
        }
    }

    fn get_receipts_t(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedTransferableReceipt>> {
        Some(vec![].into_iter())
    }

    fn get_receipts_nt(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        Some(vec![].into_iter())
    }
}

impl RedbDatabase {
    fn insert_key_event(&self, event: &KeriEvent<KeyEvent>) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;
        let value = event.encode().map_err(|_err| RedbError::WrongValue)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(EVENTS)?;
            table.insert(digest.to_str().as_str(), &value.as_ref())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    fn save_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), RedbError> {
        let digest = event.digest().map_err(|_e| RedbError::MissingDigest)?;

        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(KELS)?;
            let id = event.data.prefix.to_str();
            let sn = event.data.sn;
            table.insert((id.as_str(), sn), digest.to_str().as_bytes())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    fn insert_indexed_signatures(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        signature: &IndexedSignature,
    ) -> Result<(), RedbError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_multimap_table(SIGS)?;
            table.insert(
                (identifier.to_str().as_str(), sn),
                signature.to_str().as_bytes(),
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    fn get_event_by_digest(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<KeriEvent<KeyEvent>>, RedbError> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(EVENTS)?;

        if let Some(event) = table.get(said.to_str().as_str())? {
            let value: KeriEvent<KeyEvent> =
                serde_json::from_slice(event.value()).map_err(|_| RedbError::WrongValue)?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    fn get_signatures(
        &self,
        key: (&str, u64),
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, RedbError> {
        let read_txn = self.db.begin_read()?;

        let table = read_txn.open_multimap_table(SIGS)?;
        let signatures = table.get(key)?.map(|sig| match sig {
            Ok(sig) => std::str::from_utf8(sig.value())
                .unwrap()
                .parse::<IndexedSignature>()
                .unwrap(),
            Err(_) => todo!(),
        });
        Ok(Some(signatures))
    }

    pub fn get_kel<'a>(
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

                let said = &std::str::from_utf8(&value.value())
                    .map_err(|_e| RedbError::WrongValue)
                    .unwrap()
                    .parse()
                    .map_err(|_e| RedbError::WrongValue)
                    .unwrap();
                let event = self.get_event_by_digest(said).unwrap().unwrap();
                TimestampedSignedEventMessage::new(SignedEventMessage::new(
                    &event, signatures, None, None,
                ))
            })
            .collect()
    }

    pub fn insert_message(&self, event: &Message) -> Result<(), RedbError> {
        match event {
            Message::Notice(Notice::Event(signed_event_message)) => {
                let event = &signed_event_message.event_message;
                let signatures = &signed_event_message.signatures;
                let id = &event.data.prefix;
                let sn = event.data.sn;
                for signature in signatures {
                    self.insert_indexed_signatures(id, sn, signature)?;
                }
                self.insert_key_event(event)?;
                self.save_to_kel(event)?;
            }
            Message::Notice(Notice::NontransferableRct(_signed_nontransferable_receipt)) => todo!(),
            Message::Notice(Notice::TransferableRct(_signed_transferable_receipt)) => todo!(),
            Message::Op(_) => todo!(),
        };
        Ok(())
    }
}

#[test]
fn test_retrieve_kel() {
    use crate::actor::parse_event_stream;
    use tempfile::NamedTempFile;
    // Create test db path.
    let file_path = NamedTempFile::new().unwrap();

    // Open a sled database
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
        db.insert_message(ev).unwrap();
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

    let sigs_from_db = db
        .get_signatures((&second_id.to_str(), 0))
        .unwrap()
        .unwrap();
    assert_eq!(sigs_from_db.count(), 1);

    // Retrieve KEL in range
    let part_of_kel_events = db
        .get_kel(&first_id, 1, 2)
        .iter()
        .map(|ev| ev.signed_event_message.encode().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(part_of_kel_events, vec![rot_raw, ixn_raw]);
}
