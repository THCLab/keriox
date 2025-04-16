use std::path::Path;

use keri_core::{mailbox::MailboxResponse, prefix::IdentifierPrefix};
use rusqlite::{params, Connection};

use crate::{error::ControllerError, mailbox_updating::MailboxReminder};


/// A structure that stores the state of already retrieved mailbox events and already published receipts.
pub struct IdentifierCache {
    connection: Connection,
    own_table: String,
    groups_table: String,
    receipt_table: String,
}

impl IdentifierCache {
    pub fn new(db_file: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(db_file)?;
        let own_table_name = "own_index".to_string();
        let group_table_name = "group_index".to_string();
        let receipts_table_name = "published_receipts".to_string();

        // Create the table if it doesn't exist
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                identifier TEXT PRIMARY KEY,
                receipt INTEGER NOT NULL,
                multisig INTEGER NOT NULL,
                delegate INTEGER NOT NULL
            )",
                own_table_name
            ),
            [],
        )?;

        // Create the table if it doesn't exist
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                identifier TEXT PRIMARY KEY,
                receipt INTEGER NOT NULL,
                multisig INTEGER NOT NULL,
                delegate INTEGER NOT NULL
            )",
                group_table_name
            ),
            [],
        )?;

        // Create the table if it doesn't exist
        conn.execute(
            &format!(
                "CREATE TABLE IF NOT EXISTS {} (
                identifier TEXT PRIMARY KEY,
                sn INTEGER NOT NULL
            )",
                receipts_table_name
            ),
            [],
        )?;

        Ok(Self {
            connection: conn,
            own_table: own_table_name,
            groups_table: group_table_name,
            receipt_table: receipts_table_name,
        })
    }

    fn load_mailbox_remainder(
        &self,
        table_name: &str,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT receipt, multisig, delegate FROM {} WHERE identifier = ?1",
            table_name
        ))?;

        let mut rows = stmt.query(params![id.to_string()])?;

        // Fetch the first row (assuming there is only one match)
        if let Some(row) = rows.next()? {
            let receipt: usize = row.get(0)?;
            let multisig: usize = row.get(1)?;
            let delegate: usize = row.get(2)?;

            Ok(MailboxReminder {
                receipt,
                multisig,
                delegate,
            })
        } else {
            Ok(MailboxReminder::default())
        }
    }

    pub fn update_last_published_receipt(
        &self,
        key: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            &format!(
                "INSERT OR IGNORE INTO {} (identifier, sn)
        VALUES (?, 0);",
                self.receipt_table
            ),
            params![key.to_string()],
        )?;
        self.connection.execute(
            &format!(
                "UPDATE {} 
         SET sn = ?2
         WHERE identifier = ?1",
                self.receipt_table
            ),
            params![key.to_string(), sn,],
        )?;
        Ok(())
    }

    pub fn load_published_receipts_sn(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<usize, ControllerError> {
        let mut stmt = self.connection.prepare(&format!(
            "SELECT sn FROM {} WHERE identifier = ?1",
            self.receipt_table
        ))?;

        let mut rows = stmt.query(params![id.to_string()])?;

        // Fetch the first row (assuming there is only one match)
        if let Some(row) = rows.next()? {
            let sn: usize = row.get(0)?;
            Ok(sn)
        } else {
            Ok(0)
        }
    }

    pub fn last_asked_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(&self.own_table, id)
    }

    pub fn last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        self.load_mailbox_remainder(&self.groups_table, id)
    }

    pub fn update_mailbox_remainder(
        &self,
        table_name: &str,
        key: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), rusqlite::Error> {
        self.connection.execute(
            &format!(
                "INSERT OR IGNORE INTO {} (identifier, receipt, multisig, delegate)
        VALUES (?, 0, 0, 0);",
                table_name
            ),
            params![key.to_string()],
        )?;
        self.connection.execute(
            &format!(
                "UPDATE {} 
         SET receipt = receipt + ?1, 
             multisig = multisig + ?2, 
             delegate = delegate + ?3 
         WHERE identifier = ?4",
                table_name,
            ),
            params![
                res.receipt.len(),
                res.multisig.len(),
                res.delegate.len(),
                key.to_string()
            ],
        )?;
        Ok(())
    }

    pub fn update_last_asked_index(
        &self,
        key: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), rusqlite::Error> {
        self.update_mailbox_remainder(&self.own_table, key, res)
    }

    pub fn update_last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), rusqlite::Error> {
        self.update_mailbox_remainder(&self.groups_table, id, res)
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
