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
        // Create tables if they don't exist
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(OWN_INDEX)?;
            write_txn.open_table(GROUP_INDEX)?;
            write_txn.open_table(PUBLISHED_RECEIPTS)?;
        }
        write_txn.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    fn load_mailbox_remainder(
        &self,
        table: TableDefinition<&str, (u64, u64, u64)>,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(table)?;
        let key = id.to_string();
        if let Some(value) = tbl.get(key.as_str())? {
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
        key: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(PUBLISHED_RECEIPTS)?;
            tbl.insert(key.to_string().as_str(), sn)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn load_published_receipts_sn(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<usize, ControllerError> {
        let read_txn = self.db.begin_read()?;
        let tbl = read_txn.open_table(PUBLISHED_RECEIPTS)?;
        let key = id.to_string();
        if let Some(value) = tbl.get(key.as_str())? {
            Ok(value.value() as usize)
        } else {
            Ok(0)
        }
    }

    pub fn last_asked_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(OWN_INDEX, id)
    }

    pub fn last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(GROUP_INDEX, id)
    }

    fn update_mailbox_remainder(
        &self,
        table: TableDefinition<&str, (u64, u64, u64)>,
        key: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let write_txn = self.db.begin_write()?;
        {
            let mut tbl = write_txn.open_table(table)?;
            let key_str = key.to_string();
            let (receipt, multisig, delegate) =
                if let Some(existing) = tbl.get(key_str.as_str())? {
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
        key: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        self.update_mailbox_remainder(OWN_INDEX, key, res)
    }

    pub fn update_last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        self.update_mailbox_remainder(GROUP_INDEX, id, res)
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
    let ind = mc.last_asked_index(&id).unwrap();
    assert_eq!(ind.receipt, 0);
    assert_eq!(ind.multisig, 0);
    assert_eq!(ind.delegate, 0);

    mc.update_last_asked_index(&id, &mr).unwrap();
    let ind = mc.last_asked_index(&id).unwrap();
    assert_eq!(ind.receipt, 1);
    assert_eq!(ind.multisig, 0);
    assert_eq!(ind.delegate, 0);
}
