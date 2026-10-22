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
    /// Destroy a seed so it cannot be recovered from this store. Deleting
    /// an absent seed succeeds.
    fn delete(&self, alias: &str, name: &str) -> Result<()>;
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

    /// Overwrites the file with zeros and syncs it before unlinking, so the
    /// seed does not linger in the freed blocks of a plain filesystem.
    /// Copy-on-write filesystems and SSD wear levelling may still keep old
    /// copies; use an OS keychain where that matters.
    fn delete(&self, alias: &str, name: &str) -> Result<()> {
        use std::io::Write;

        let path = self.root.join(alias).join(name);
        let len = match std::fs::metadata(&path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(Error::PersistenceError(format!("cannot stat {name}: {e}"))),
        };
        let shred = || -> std::io::Result<()> {
            let mut file = std::fs::OpenOptions::new().write(true).open(&path)?;
            file.write_all(&vec![0u8; len as usize])?;
            file.sync_all()?;
            std::fs::remove_file(&path)
        };
        shred().map_err(|e| Error::PersistenceError(format!("cannot delete {name}: {e}")))
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

    fn delete(&self, alias: &str, name: &str) -> Result<()> {
        self.seeds
            .write()
            .map_err(|_| Error::PersistenceError("secrets lock poisoned".into()))?
            .remove(&(alias.to_string(), name.to_string()));
        Ok(())
    }
}
