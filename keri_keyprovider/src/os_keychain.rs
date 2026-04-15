//! OS-native keychain provider.
//!
//! Stores encrypted seeds in the platform's native credential store:
//! - **macOS**: Keychain Services
//! - **Windows**: Credential Manager (DPAPI-encrypted)
//! - **Linux**: Secret Service (GNOME Keyring / KDE Wallet) via DBus
//!
//! The key is unlocked by reading the seed from the OS keychain at runtime.
//! On supported platforms, the OS may prompt for biometric or password unlock.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use crate::{
    software::SoftwareKeyProvider, KeyProvider, KeyProviderError, KeyProviderFactory,
    PublicKeyData, Result, SignatureAlgorithm,
};

/// Persistent key provider backed by the OS-native keychain.
///
/// The seed is stored as a credential in the OS keychain. On unlock,
/// the seed is read out and held in an `Arc<SoftwareKeyProvider>` in memory.
/// The in-memory key is dropped (and zeroized by ed25519-dalek) on lock.
pub struct OsKeychainProvider {
    label: String,
    service_name: String,
    algorithm: SignatureAlgorithm,
    public_data: PublicKeyData,
    inner: Mutex<Option<Arc<SoftwareKeyProvider>>>,
}

impl OsKeychainProvider {
    /// Create a new key in the OS keychain.
    pub fn create(
        label: impl Into<String>,
        service_name: impl Into<String>,
        algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        let label = label.into();
        let service_name = service_name.into();

        let provider = SoftwareKeyProvider::generate(&label, algorithm)?;
        let public_data = provider.public_key().clone();

        let seed = provider.ed25519_seed_bytes().ok_or_else(|| {
            KeyProviderError::UnsupportedAlgorithm("only Ed25519 supported".into())
        })?;

        let entry = keyring::Entry::new(&service_name, &label).map_err(|e| {
            KeyProviderError::Other(format!("failed to create keychain entry: {e}"))
        })?;
        entry
            .set_password(&hex_encode(&seed))
            .map_err(|e| KeyProviderError::Other(format!("failed to write to keychain: {e}")))?;

        Ok(Self {
            label,
            service_name,
            algorithm,
            public_data,
            inner: Mutex::new(Some(Arc::new(provider))),
        })
    }

    /// Open an existing key from the OS keychain (initially locked).
    ///
    /// Call `unlock()` to load the key material.
    pub fn open(
        label: impl Into<String>,
        service_name: impl Into<String>,
        algorithm: SignatureAlgorithm,
        public_data: PublicKeyData,
    ) -> Self {
        Self {
            label: label.into(),
            service_name: service_name.into(),
            algorithm,
            public_data,
            inner: Mutex::new(None),
        }
    }

    /// Unlock by reading the seed from the OS keychain.
    pub fn unlock(&self) -> Result<()> {
        let entry = keyring::Entry::new(&self.service_name, &self.label)
            .map_err(|e| KeyProviderError::Other(format!("failed to open keychain entry: {e}")))?;
        let hex_seed = entry.get_password().map_err(|e| {
            KeyProviderError::AuthenticationFailed(format!("failed to read from keychain: {e}"))
        })?;

        let seed_bytes = hex_to_bytes(&hex_seed)?;
        let seed_arr: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyProviderError::InvalidKeyMaterial("seed must be 32 bytes".into()))?;

        let provider = SoftwareKeyProvider::from_ed25519_bytes(&self.label, &seed_arr)?;

        let mut inner = self.inner.lock().unwrap();
        *inner = Some(Arc::new(provider));

        Ok(())
    }

    /// Lock the provider, dropping in-memory key material.
    pub fn lock(&self) {
        let mut inner = self.inner.lock().unwrap();
        *inner = None;
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return Err(KeyProviderError::InvalidKeyMaterial(
            "odd-length hex string".into(),
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| KeyProviderError::InvalidKeyMaterial(format!("invalid hex: {e}")))
        })
        .collect()
}

#[async_trait]
impl KeyProvider for OsKeychainProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let inner = {
            let guard = self.inner.lock().unwrap();
            guard.clone().ok_or(KeyProviderError::Locked)?
        };
        inner.sign(message).await
    }

    fn public_key(&self) -> &PublicKeyData {
        &self.public_data
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn supports_export(&self) -> bool {
        true
    }
}

/// Factory that creates and manages keys in the OS keychain.
pub struct OsKeychainProviderFactory {
    service_name: String,
}

impl OsKeychainProviderFactory {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

#[async_trait]
impl KeyProviderFactory for OsKeychainProviderFactory {
    async fn create(
        &self,
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Arc<dyn KeyProvider>> {
        let provider = OsKeychainProvider::create(label, &self.service_name, algorithm)?;
        Ok(Arc::new(provider))
    }

    async fn open(&self, label: &str) -> Result<Arc<dyn KeyProvider>> {
        let entry = keyring::Entry::new(&self.service_name, label)
            .map_err(|e| KeyProviderError::Other(format!("failed to open keychain entry: {e}")))?;

        let hex_seed = entry.get_password().map_err(|e| {
            KeyProviderError::NotFound(format!("key '{label}' not found in keychain: {e}"))
        })?;

        let seed_bytes = hex_to_bytes(&hex_seed)?;
        let seed_arr: [u8; 32] = seed_bytes
            .as_slice()
            .try_into()
            .map_err(|_| KeyProviderError::InvalidKeyMaterial("seed must be 32 bytes".into()))?;

        let provider = SoftwareKeyProvider::from_ed25519_bytes(label, &seed_arr)?;
        let public_data = provider.public_key().clone();

        let os_provider = OsKeychainProvider {
            label: label.to_string(),
            service_name: self.service_name.clone(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_data,
            inner: Mutex::new(Some(Arc::new(provider))),
        };

        Ok(Arc::new(os_provider))
    }

    async fn list(&self) -> Result<Vec<String>> {
        Err(KeyProviderError::UnsupportedOperation(
            "OS keychain does not support listing keys".into(),
        ))
    }

    async fn delete(&self, label: &str) -> Result<()> {
        let entry = keyring::Entry::new(&self.service_name, label)
            .map_err(|e| KeyProviderError::Other(format!("failed to open keychain entry: {e}")))?;
        entry
            .delete_credential()
            .map_err(|e| KeyProviderError::Other(format!("failed to delete from keychain: {e}")))?;
        Ok(())
    }
}
