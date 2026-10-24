//! The identifiers the witness poller tracks, kept on disk so that polling
//! resumes after a restart.

use std::path::Path;

use keri_core::prefix::IdentifierPrefix;
use redb::{Database, ReadableTable, TableDefinition};

/// Tracked identifier -> whether it is subscribed.
const TRACKED: TableDefinition<&str, bool> = TableDefinition::new("tracked_aids");

pub(crate) struct TrackedAidsStore(Database);

impl TrackedAidsStore {
    pub(crate) fn open(path: &Path) -> Result<Self, redb::Error> {
        let db = Database::create(path)?;
        let txn = db.begin_write()?;
        txn.open_table(TRACKED)?;
        txn.commit()?;
        Ok(Self(db))
    }

    /// Every tracked identifier, with whether it is subscribed.
    pub(crate) fn load(&self) -> Result<Vec<(IdentifierPrefix, bool)>, redb::Error> {
        let txn = self.0.begin_read()?;
        let table = txn.open_table(TRACKED)?;
        let mut tracked = vec![];
        for entry in table.iter()? {
            let (id, subscribed) = entry?;
            match id.value().parse() {
                Ok(id) => tracked.push((id, subscribed.value())),
                Err(_) => tracing::warn!(id = id.value(), "skipping unreadable tracked AID"),
            }
        }
        Ok(tracked)
    }

    pub(crate) fn save(&self, id: &IdentifierPrefix, subscribed: bool) -> Result<(), redb::Error> {
        let txn = self.0.begin_write()?;
        txn.open_table(TRACKED)?
            .insert(id.to_string().as_str(), subscribed)?;
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn remove(&self, id: &IdentifierPrefix) -> Result<(), redb::Error> {
        let txn = self.0.begin_write()?;
        txn.open_table(TRACKED)?.remove(id.to_string().as_str())?;
        txn.commit()?;
        Ok(())
    }
}
