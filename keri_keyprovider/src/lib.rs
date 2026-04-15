//! # keri-keyprovider
//!
//! A standalone, decoupled cryptographic key provider interface.
//!
//! This crate defines the [`KeyProvider`] and [`KeyProviderFactory`] traits —
//! abstracting over **any** signing backend: in-memory software keys, encrypted
//! files, OS keystores, HSMs, cloud KMS services, or hardware secure enclaves.
//!
//! The traits are fully independent of the keriox stack and can be used by any
//! Rust project that needs pluggable signing backends.

mod error;
mod types;

pub use error::{KeyProviderError, Result};
pub use types::{PublicKeyData, SignatureAlgorithm};

use async_trait::async_trait;
use std::sync::Arc;

/// Core abstraction: anything that can sign a message.
///
/// Implementations range from in-memory software keys to remote HSMs and cloud
/// KMS services. The private key material **never** needs to be exposed to the
/// consumer — only the `sign()` operation and the public key.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    /// Sign a message and return raw signature bytes.
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>>;

    /// Return the public key for this provider.
    fn public_key(&self) -> &PublicKeyData;

    /// The signature algorithm this provider uses.
    fn algorithm(&self) -> SignatureAlgorithm {
        self.public_key().algorithm
    }

    /// Human-readable label for this key (e.g. alias, key ID, HSM slot).
    fn label(&self) -> &str;

    /// Whether this provider supports key rotation.
    fn supports_rotation(&self) -> bool {
        false
    }

    /// Rotate: replace the current key with a new one.
    async fn rotate(&mut self, _new_next_public_key: PublicKeyData) -> Result<()> {
        Err(KeyProviderError::unsupported("rotate"))
    }

    /// Whether this provider can export encrypted key material.
    fn supports_export(&self) -> bool {
        false
    }

    /// Export the key material in encrypted form for backup/migration.
    async fn export_encrypted(&self, _passphrase: &str) -> Result<EncryptedKeyExport> {
        Err(KeyProviderError::unsupported("export"))
    }
}

/// Factory trait for creating and managing key providers.
///
/// A factory owns the lifecycle of key providers: creating new ones, opening
/// existing ones, listing them, and deleting them.
#[async_trait]
pub trait KeyProviderFactory: Send + Sync {
    /// Create a new random key provider with the given label and algorithm.
    async fn create(
        &self,
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Arc<dyn KeyProvider>>;

    /// Open an existing key provider by its label.
    async fn open(&self, label: &str) -> Result<Arc<dyn KeyProvider>>;

    /// List all labels managed by this factory.
    async fn list(&self) -> Result<Vec<String>>;

    /// Delete a key provider by label.
    async fn delete(&self, label: &str) -> Result<()>;
}

/// Encrypted key export package for backup and cross-device migration.
///
/// The seed is encrypted with XChaCha20-Poly1305 using a key derived from
/// the user's passphrase via Argon2id. This format is self-contained and
/// can be serialized for storage or transfer.
#[derive(Debug, Clone)]
pub struct EncryptedKeyExport {
    /// Format version (currently 1).
    pub version: u8,
    /// The label/alias of the key.
    pub label: String,
    /// The algorithm used by the key.
    pub algorithm: SignatureAlgorithm,
    /// Argon2id salt (32 bytes).
    pub salt: Vec<u8>,
    /// XChaCha20-Poly1305 nonce (24 bytes).
    pub nonce: Vec<u8>,
    /// Encrypted seed bytes (ciphertext + 16-byte Poly1305 tag).
    pub ciphertext: Vec<u8>,
    /// Argon2id parameters used for key derivation.
    pub kdf_params: KdfParams,
}

/// Argon2id KDF parameters stored alongside the encrypted export.
#[derive(Debug, Clone)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub mem_cost: u32,
    /// Number of iterations (time cost).
    pub time_cost: u32,
    /// Parallelism (number of lanes).
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            mem_cost: 64 * 1024,
            time_cost: 3,
            parallelism: 1,
        }
    }
}

#[cfg(feature = "software")]
pub mod software;

#[cfg(feature = "file-encrypted")]
pub mod file_encrypted;

#[cfg(feature = "os-keychain")]
pub mod os_keychain;

#[cfg(feature = "host")]
pub mod host;
