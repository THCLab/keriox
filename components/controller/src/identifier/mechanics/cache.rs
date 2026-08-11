use std::{path::Path, sync::Arc};

use keri_core::{mailbox::MailboxResponse, prefix::IdentifierPrefix};
use redb::{Database, ReadableTable, TableDefinition};

use crate::{error::ControllerError, mailbox_updating::MailboxReminder};

const OWN_INDEX: TableDefinition<&str, (u64, u64, u64)> = TableDefinition::new("own_index");
const GROUP_INDEX: TableDefinition<&str, (u64, u64, u64)> = TableDefinition::new("group_index");
const PUBLISHED_RECEIPTS: TableDefinition<&str, u64> = TableDefinition::new("published_receipts");

/// A structure that stores the state of already retrieved mailbox events and already published receipts.
pub struct IdentifierCache {
    db: Arc<Database>,
}

impl IdentifierCache {
    pub fn new(db_file: &Path) -> Result<Self, ControllerError> {
        let db = Database::create(db_file)?;
        Self::from_database(Arc::new(db))
    }

    /// Cache backed by redb's in-memory backend — nothing touches disk.
    pub fn new_in_memory() -> Result<Self, ControllerError> {
        let db = Database::builder()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|e| ControllerError::CacheError(e.to_string()))?;
        Self::from_database(Arc::new(db))
    }

    /// Build on an already-open redb `Database` (file-backed or in-memory).
    pub fn from_database(db: Arc<Database>) -> Result<Self, ControllerError> {
        // Create tables if they don't exist
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(OWN_INDEX)?;
            write_txn.open_table(GROUP_INDEX)?;
            write_txn.open_table(PUBLISHED_RECEIPTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Mailbox read positions and published receipts are tracked per
    /// (subject identifier, witness) pair: several identifiers can share
    /// one database (shared store layout), and each has its own mailbox at
    /// each witness — keying on the witness alone would make them consume
    /// each other's read positions.
    fn composite_key(subject: &IdentifierPrefix, witness: &IdentifierPrefix) -> String {
        format!("{subject}|{witness}")
    }

    fn load_mailbox_remainder(
        &self,
        table: TableDefinition<&str, (u64, u64, u64)>,
        key: &str,
    ) -> Result<MailboxReminder, ControllerError> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(table)?;
        if let Some(value) = tbl.get(key)? {
            let (receipt, multisig, delegate) = value.value();
            Ok(MailboxReminder {
                receipt: receipt as usize,
                multisig: multisig as usize,
                delegate: delegate as usize,
            })
        } else {
            Ok(MailboxReminder::default())
        }
    }

    pub fn update_last_published_receipt(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(PUBLISHED_RECEIPTS)?;
            tbl.insert(Self::composite_key(subject, witness).as_str(), sn)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn load_published_receipts_sn(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
    ) -> Result<usize, ControllerError> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(PUBLISHED_RECEIPTS)?;
        let key = Self::composite_key(subject, witness);
        if let Some(value) = tbl.get(key.as_str())? {
            Ok(value.value() as usize)
        } else {
            Ok(0)
        }
    }

    pub fn last_asked_index(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(OWN_INDEX, &Self::composite_key(subject, witness))
    }

    pub fn last_asked_group_index(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(GROUP_INDEX, &Self::composite_key(subject, witness))
    }

    fn update_mailbox_remainder(
        &self,
        table: TableDefinition<&str, (u64, u64, u64)>,
        key_str: String,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(table)?;
            let (receipt, multisig, delegate) = if let Some(existing) = tbl.get(key_str.as_str())? {
                existing.value()
            } else {
                (0, 0, 0)
            };
            tbl.insert(
                key_str.as_str(),
                (
                    receipt + res.receipt.len() as u64,
                    multisig + res.multisig.len() as u64,
                    delegate + res.delegate.len() as u64,
                ),
            )?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn update_last_asked_index(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        self.update_mailbox_remainder(OWN_INDEX, Self::composite_key(subject, witness), res)
    }

    /// Forget how much of `subject`'s mailbox has been read at
    /// `witness`, so the next query starts from the beginning again.
    ///
    /// The read position advances by the number of items a response
    /// carried, not by the number that could be used. An item consumed
    /// while it was not yet applicable — a witness receipt for an event
    /// still waiting on its delegating anchor, say — is therefore never
    /// served again, and whatever needed it waits forever. A caller
    /// that knows it is still missing something can ask for the whole
    /// mailbox again.
    pub fn reset_last_asked_group_index(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(GROUP_INDEX)?;
            tbl.insert(Self::composite_key(subject, witness).as_str(), (0, 0, 0))?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn update_last_asked_group_index(
        &self,
        subject: &IdentifierPrefix,
        witness: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        self.update_mailbox_remainder(GROUP_INDEX, Self::composite_key(subject, witness), res)
    }
}

#[test]
fn test_query_cache() {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let mc = IdentifierCache::new(Path::new(tmp.path())).unwrap();
    let m_res = r#"{"receipt":[{"body":{"v":"KERI10JSON000091_","t":"rct","d":"EGhf8TN8UUIPCK5aHaU3qTGjCBTvWUL2ahhtT3xFflBs","i":"EGhf8TN8UUIPCK5aHaU3qTGjCBTvWUL2ahhtT3xFflBs","s":"0"},"signatures":[{"Couplet":[["BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4","0BDF6GYBes5JYpGFbrPWlgqirCNKiwN3gUnoYxnlLnqF7TSa5qsbt32FltbGQH3JIRmN3qEkIxpN0Woo0FN4PGQM"]]}]}],"multisig":[],"delegate":[]}"#;
    let mr: MailboxResponse = serde_json::from_str(&m_res).unwrap();
    let id: IdentifierPrefix = "BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"
        .parse()
        .unwrap();
    let witness: IdentifierPrefix = "BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
        .parse()
        .unwrap();
    let ind = mc.last_asked_index(&id, &witness).unwrap();
    assert_eq!(ind.receipt, 0);
    assert_eq!(ind.multisig, 0);
    assert_eq!(ind.delegate, 0);

    mc.update_last_asked_index(&id, &witness, &mr).unwrap();
    let ind = mc.last_asked_index(&id, &witness).unwrap();
    assert_eq!(ind.receipt, 1);
    assert_eq!(ind.multisig, 0);
    assert_eq!(ind.delegate, 0);

    // A consumed-but-unusable item can be asked for again.
    mc.update_last_asked_group_index(&id, &witness, &mr).unwrap();
    assert_eq!(mc.last_asked_group_index(&id, &witness).unwrap().receipt, 1);
    mc.reset_last_asked_group_index(&id, &witness).unwrap();
    assert_eq!(
        mc.last_asked_group_index(&id, &witness).unwrap().receipt,
        0,
        "resetting must re-serve the whole mailbox"
    );

    // A different identifier sharing the same witness (and database) has
    // its own independent read position.
    let other: IdentifierPrefix = "BP55jNfeiVfGn7-M5ugPCst9FlUOSaYourMDdxysMoX8"
        .parse()
        .unwrap();
    let ind = mc.last_asked_index(&other, &witness).unwrap();
    assert_eq!(ind.receipt, 0);
}
