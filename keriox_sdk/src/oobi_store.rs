//! OOBI storage for looking up and registering signed OOBI replies.
//!
//! This wraps `keri_core::oobi_manager::OobiManager` with a clean API
//! that hides the database backend.

use std::path::Path;
use std::sync::Arc;

use keri_core::database::redb::RedbDatabase;
use keri_core::oobi::Role;
use keri_core::oobi_manager::RedbOobiManager;
use keri_core::query::reply_event::{ReplyEvent, SignedReply};

use crate::error::{Error, Result};
use crate::IdentifierPrefix;

/// Persistent OOBI reply storage backed by redb.
///
/// Stores and retrieves signed OOBI replies (location schemes, end-role
/// entries). This is separate from KEL verification — it's purely for
/// looking up where to reach an identifier or what role it serves.
pub struct OobiStore {
    manager: RedbOobiManager,
}

impl OobiStore {
    /// Open (or create) an OOBI store at the given directory path.
    ///
    /// A `oobi_db.redb` file will be created inside `dir`.
    pub fn open(dir: &Path) -> Result<Self> {
        let db = Arc::new(
            RedbDatabase::new(&dir.join("oobi_db"))
                .map_err(|e| Error::PersistenceError(e.to_string()))?,
        );
        let manager =
            RedbOobiManager::new(db).map_err(|e| Error::PersistenceError(e.to_string()))?;
        Ok(Self { manager })
    }

    /// Register a signed OOBI reply (verified externally).
    pub fn register(&self, reply: &SignedReply) -> Result<()> {
        self.manager
            .process_oobi(reply)
            .map_err(|e| Error::PersistenceError(e.to_string()))
    }

    /// Register multiple signed OOBI replies, returning the count of successes.
    pub fn register_many(&self, replies: &[SignedReply]) -> usize {
        let mut ok = 0;
        for r in replies {
            if self.register(r).is_ok() {
                ok += 1;
            }
        }
        ok
    }

    /// Get stored location schemes for an identifier.
    pub fn get_location(&self, id: &IdentifierPrefix) -> Vec<ReplyEvent> {
        self.manager.get_loc_scheme(id).unwrap_or_default()
    }

    /// Get stored end-role entries for an identifier and role.
    pub fn get_end_role(&self, id: &IdentifierPrefix, role: Role) -> Vec<SignedReply> {
        self.manager
            .get_end_role(id, role)
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}
