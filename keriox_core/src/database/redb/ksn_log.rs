use std::sync::Arc;

use redb::{Database, TableDefinition};
use said::SelfAddressingIdentifier;

use crate::{
    error::Error,
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
};

use super::{execute_in_transaction, rkyv_adapter, RedbError, WriteTxnMode};

/// Key State Notices store. (event digest) -> ksn
/// The `KSN` table directly stores the event data, which other tables reference
/// by its digest.
const KSN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("ksns");

///
const ACCEPTED_KSN: TableDefinition<(&str, &str), &str> = TableDefinition::new("accepted");

/// Stores last accepted Key State Notices for performing BADA logic.  
pub struct AcceptedKsn {
    pub ksn_log: Arc<KsnLogDatabase>,
    db: Arc<Database>,
}

impl AcceptedKsn {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        let ksn_log = Arc::new(KsnLogDatabase::new(db.clone())?);
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(ACCEPTED_KSN)?;
        }
        write_txn.commit()?;
        Ok(Self { db, ksn_log })
    }

    pub fn insert(&self, reply: SignedReply) -> Result<(), RedbError> {
        let (from_who, about_who) = if let ReplyRoute::Ksn(id, ksn) = reply.reply.get_route() {
            Ok((id, ksn.state.prefix))
        } else {
            Err(Error::SemanticError("Wrong event type".into()))
        }
        .unwrap();
        let write_txn = self.db.begin_write()?;
        {
            let mut table = (&write_txn).open_table(ACCEPTED_KSN)?;
            table.insert(
                (
                    about_who.to_string().as_str(),
                    from_who.to_string().as_str(),
                ),
                reply.reply.digest().unwrap().to_string().as_str(),
            )?;

            self.ksn_log
                .log_reply(&WriteTxnMode::UseExisting(&write_txn), &reply)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn get_all(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, RedbError> {
        let str_id = id.to_string();
        let start = (str_id.as_str(), "");

        // End of the range: ("apple\u{FFFD}", "")
        // Adding a character greater than any normal Unicode character ensures the end is exclusive
        let mut end_prefix = str_id.to_owned();
        end_prefix.push('\u{FFFD}'); // or use '\u{10FFFF}' for max valid Unicode scalar
        let end = (end_prefix.as_str(), "");

        let corresponding_digests = {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(ACCEPTED_KSN).unwrap();
            table.range(start..end)
        }?;

        corresponding_digests
            .filter_map(|entry| {
                let (_, value) = entry.unwrap();
                let id: SelfAddressingIdentifier = value.value().parse().unwrap();
                self.ksn_log.get_signed_reply(&id).transpose()
            })
            .collect()
    }

    pub fn get(
        &self,
        id: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
    ) -> Result<Option<SignedReply>, RedbError> {
        let corresponding_digest = {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(ACCEPTED_KSN).unwrap();
            table.get((id.to_string().as_str(), from_who.to_string().as_str()))?
        };
        match corresponding_digest {
            Some(digest) => {
                let id: SelfAddressingIdentifier = digest.value().parse().unwrap();
                self.ksn_log.get_signed_reply(&id)
            }
            None => Ok(None),
        }
    }
}

/// Stores incoming Replay messages with inside Key State Notices.  
/// Key in the table is a digest of the event, and value is the event itself.
pub(crate) struct KsnLogDatabase {
    db: Arc<Database>,
}

impl KsnLogDatabase {
    pub fn new(db: Arc<Database>) -> Result<Self, RedbError> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(KSN)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    /// Saves provided event into key event table. Key is it's digest and value is event.
    fn insert_ksn(&self, txn_mode: &WriteTxnMode, event: &SignedReply) -> Result<(), RedbError> {
        let digest = event
            .reply
            .digest()
            .map_err(|_e| RedbError::MissingDigest)?;
        let value = serde_cbor::to_vec(event).unwrap();

        execute_in_transaction(self.db.clone(), txn_mode, |write_txn| {
            let mut table = write_txn.open_table(KSN)?;
            let key = rkyv_adapter::serialize_said(&digest)?;
            table.insert(key.as_slice(), &value.as_ref())?;
            dbg!("Inserted KSN: key: {:?}, \nvalue: {:?}, ", digest, event);
            Ok(())
        })
    }

    pub fn log_reply(
        &self,
        txn_mode: &WriteTxnMode,
        signed_event: &SignedReply,
    ) -> Result<(), RedbError> {
        self.insert_ksn(&txn_mode, &signed_event)?;
        Ok(())
    }

    pub fn get_signed_reply(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedReply>, RedbError> {
        let key = rkyv_adapter::serialize_said(said)?;

        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(KSN)?;

        if let Some(event) = table.get(key.as_slice())? {
            let bytes = event.value().to_vec();
            let deser: SignedReply = serde_cbor::from_slice(&bytes).unwrap();
            Ok(Some(deser))
        } else {
            Ok(None)
        }
    }
}
