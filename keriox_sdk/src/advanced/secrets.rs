//! Pluggable storage for signing seeds (software-managed keys).
//!
//! Seeds are the one piece of SDK state that must never enter the event or
//! metadata databases: they are private key material. With an external key
//! provider (mobile keystore, HSM — the `keyprovider` feature) the SDK
//! stores no seeds at all and this module is not involved.
//!
//! For software keys, [`KeriStore`](crate::advanced::store::KeriStore)
//! writes seeds through a [`SecretsStore`]. The default,
//! [`FileSecretsStore`], keeps today's plaintext-file layout
//! (`<root>/<alias>/priv_key`, `next_priv_key`) for compatibility;
//! platforms should plug an OS-keychain implementation (Android Keystore,
//! iOS Keychain, Secret Service) instead. [`MemorySecretsStore`] holds
//! seeds in memory only — for tests and ephemeral identities.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use crate::advanced::error::{Error, Result};

/// Storage backend for signing seeds.
///
/// `name` is the seed's role within the alias: `"priv_key"` (current) or
/// `"next_priv_key"` (pre-rotation). Values are KERI canonical seed text.
pub trait SecretsStore: Send + Sync {
    /// Persist a seed. Overwrites any previous value.
    fn store(&self, alias: &str, name: &str, seed: &str) -> Result<()>;
    /// Load a seed; `Ok(None)` when absent.
    fn load(&self, alias: &str, name: &str) -> Result<Option<String>>;
}

/// The default backend: one plaintext file per seed under the alias
/// directory — exactly the historical layout, so existing stores keep
/// working. Prefer an OS-keychain implementation in production.
pub struct FileSecretsStore {
    root: PathBuf,
}

impl FileSecretsStore {
    /// Seeds live under `<root>/<alias>/<name>`.
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl SecretsStore for FileSecretsStore {
    fn store(&self, alias: &str, name: &str, seed: &str) -> Result<()> {
        let dir = self.root.join(alias);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;
        std::fs::write(dir.join(name), seed)
            .map_err(|e| Error::PersistenceError(format!("cannot write {name}: {e}")))
    }

    fn load(&self, alias: &str, name: &str) -> Result<Option<String>> {
        match std::fs::read_to_string(self.root.join(alias).join(name)) {
            Ok(content) => Ok(Some(content)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::PersistenceError(format!("cannot read {name}: {e}"))),
        }
    }
}

/// Seeds held in memory only — gone when the store is dropped. Combine
/// with [`StorageConfig::InMemory`](crate::advanced::types::StorageConfig::InMemory)
/// for a store that touches no filesystem at all.
#[derive(Default)]
pub struct MemorySecretsStore {
    seeds: RwLock<HashMap<(String, String), String>>,
}

impl MemorySecretsStore {
    /// An empty in-memory secrets store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl SecretsStore for MemorySecretsStore {
    fn store(&self, alias: &str, name: &str, seed: &str) -> Result<()> {
        self.seeds
            .write()
            .map_err(|_| Error::PersistenceError("secrets lock poisoned".into()))?
            .insert((alias.to_string(), name.to_string()), seed.to_string());
        Ok(())
    }

    fn load(&self, alias: &str, name: &str) -> Result<Option<String>> {
        Ok(self
            .seeds
            .read()
            .map_err(|_| Error::PersistenceError("secrets lock poisoned".into()))?
            .get(&(alias.to_string(), name.to_string()))
            .cloned())
    }
}
