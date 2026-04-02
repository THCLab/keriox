//! Encrypted file-backed key provider.
//!
//! Seeds are encrypted at rest using XChaCha20-Poly1305 with a key derived
//! from the user's passphrase via Argon2id. An auto-lock mechanism zeroes
//! in-memory key material after a configurable timeout.

use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chacha20poly1305::{
    aead::Aead, Key, KeyInit, XChaCha20Poly1305, XNonce,
};
use argon2::{Argon2, Algorithm, Version};
use rand::RngCore;
use zeroize::Zeroize;

use crate::{
    software::SoftwareKeyProvider,
    EncryptedKeyExport, KeyProvider, KeyProviderError, KeyProviderFactory, KdfParams, PublicKeyData,
    Result, SignatureAlgorithm,
};

const FILE_VERSION: u8 = 1;
const NONCE_SIZE: usize = 24;
const SALT_SIZE: usize = 32;

pub(crate) fn encrypt_seed(
    passphrase: &[u8],
    seed: &[u8],
    label: &str,
    algorithm: SignatureAlgorithm,
) -> Result<EncryptedKeyExport> {
    let params = KdfParams::default();
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);

    let derived_key = derive_key(passphrase, &salt, &params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let nonce = XNonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce, seed)
        .map_err(|e| KeyProviderError::EncryptionError(format!("encryption failed: {e}")))?;

    Ok(EncryptedKeyExport {
        version: FILE_VERSION,
        label: label.to_string(),
        algorithm,
        salt,
        nonce: nonce.to_vec(),
        ciphertext,
        kdf_params: params,
    })
}

fn derive_key(passphrase: &[u8], salt: &[u8], params: &KdfParams) -> Result<[u8; 32]> {
    let config = argon2::Params::new(params.mem_cost, params.time_cost, params.parallelism, Some(32))
        .map_err(|e| KeyProviderError::EncryptionError(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, config);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| KeyProviderError::EncryptionError(format!("argon2 failed: {e}")))?;
    Ok(key)
}

fn decrypt_seed(passphrase: &[u8], export: &EncryptedKeyExport) -> Result<Vec<u8>> {
    let derived_key = derive_key(passphrase, &export.salt, &export.kdf_params)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&derived_key));
    let nonce = XNonce::from_slice(&export.nonce);
    cipher
        .decrypt(nonce, export.ciphertext.as_slice())
        .map_err(|_| KeyProviderError::AuthenticationFailed("wrong passphrase or corrupted data".into()))
}

/// Persistent key provider backed by encrypted files on disk.
///
/// The key file stores:
/// ```text
/// version (1B) | algorithm (1B) | nonce (24B) | salt (32B) |
/// mem_cost (4B LE) | time_cost (4B LE) | parallelism (4B LE) |
/// ciphertext + tag
/// ```
///
/// After creation or explicit unlock, the decrypted key is held in memory
/// until the auto-lock timeout expires.
pub struct FileEncryptedProvider {
    label: String,
    path: PathBuf,
    algorithm: SignatureAlgorithm,
    public_data: PublicKeyData,
    auto_lock_timeout: Duration,
    unlocked: std::sync::Mutex<UnlockedState>,
}

struct UnlockedState {
    inner: Option<Arc<SoftwareKeyProvider>>,
    last_used: Instant,
    seed: Option<Vec<u8>>,
}

impl FileEncryptedProvider {
    /// Create a new encrypted key provider, writing the encrypted seed to disk.
    ///
    /// The passphrase is used to derive the encryption key via Argon2id.
    pub fn create(
        label: impl Into<String>,
        path: PathBuf,
        algorithm: SignatureAlgorithm,
        passphrase: &[u8],
        auto_lock_timeout: Duration,
    ) -> Result<Self> {
        let provider = SoftwareKeyProvider::generate(label.into(), algorithm)?;
        let seed = provider
            .ed25519_seed_bytes()
            .ok_or_else(|| KeyProviderError::UnsupportedAlgorithm("only Ed25519 supported".into()))?;

        let export = encrypt_seed(passphrase, &seed, provider.label(), algorithm)?;
        write_key_file(&path, &export)?;

        let public_data = provider.public_key().clone();
        let label = provider.label().to_string();

        Ok(Self {
            label,
            path,
            algorithm,
            public_data,
            auto_lock_timeout,
            unlocked: std::sync::Mutex::new(UnlockedState {
                inner: Some(Arc::new(provider)),
                last_used: Instant::now(),
                seed: Some(seed.to_vec()),
            }),
        })
    }

    /// Open an existing encrypted key file.
    ///
    /// The key remains locked until [`unlock()`](Self::unlock) is called.
    pub fn open(
        label: impl Into<String>,
        path: PathBuf,
        auto_lock_timeout: Duration,
    ) -> Result<Self> {
        let export = read_key_file(&path)?;

        // Derive public key from the algorithm (we can't decrypt without passphrase)
        let public_data = PublicKeyData::new(export.algorithm, vec![]);

        Ok(Self {
            label: label.into(),
            path,
            algorithm: export.algorithm,
            public_data,
            auto_lock_timeout,
            unlocked: std::sync::Mutex::new(UnlockedState {
                inner: None,
                last_used: Instant::now(),
                seed: None,
            }),
        })
    }

    /// Unlock the key with the given passphrase.
    pub async fn unlock(&self, passphrase: &[u8]) -> Result<()> {
        let export = read_key_file(&self.path)?;
        let seed = decrypt_seed(passphrase, &export)?;

        let provider = match export.algorithm {
            SignatureAlgorithm::Ed25519 => {
                let seed_arr: [u8; 32] = seed
                    .as_slice()
                    .try_into()
                    .map_err(|_| KeyProviderError::InvalidKeyMaterial("seed must be 32 bytes".into()))?;
                SoftwareKeyProvider::from_ed25519_bytes(&self.label, &seed_arr)?
            }
            SignatureAlgorithm::EcdsaSecp256k1 => {
                return Err(KeyProviderError::UnsupportedAlgorithm(
                    "secp256k1 file encryption not yet implemented".into(),
                ));
            }
        };

        let mut state = self.unlocked.lock().unwrap();
        state.last_used = Instant::now();
        state.inner = Some(Arc::new(provider));
        state.seed = Some(seed);

        Ok(())
    }

    async fn ensure_unlocked(&self) -> Result<()> {
        let mut state = self.unlocked.lock().unwrap();
        if state.inner.is_none() {
            return Err(KeyProviderError::Locked);
        }
        if state.last_used.elapsed() > self.auto_lock_timeout {
            state.inner.take();
            if let Some(ref mut seed) = state.seed {
                Zeroize::zeroize(seed);
                state.seed.take();
            }
            return Err(KeyProviderError::Locked);
        }
        state.last_used = Instant::now();
        Ok(())
    }
}

fn write_key_file(path: &Path, export: &EncryptedKeyExport) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut buf = Vec::with_capacity(128);
    buf.push(export.version);
    buf.push(match export.algorithm {
        SignatureAlgorithm::Ed25519 => 0,
        SignatureAlgorithm::EcdsaSecp256k1 => 1,
    });
    buf.extend_from_slice(&export.nonce);
    buf.extend_from_slice(&export.salt);
    buf.extend_from_slice(&export.kdf_params.mem_cost.to_le_bytes());
    buf.extend_from_slice(&export.kdf_params.time_cost.to_le_bytes());
    buf.extend_from_slice(&export.kdf_params.parallelism.to_le_bytes());
    buf.extend_from_slice(&export.ciphertext);

    let mut f = std::fs::File::create(path)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    Ok(())
}

fn read_key_file(path: &Path) -> Result<EncryptedKeyExport> {
    let data = std::fs::read(path)?;
    if data.len() < 66 {
        // 1 + 1 + 24 + 32 + 4 + 4 = 66 minimum (before ciphertext)
        return Err(KeyProviderError::InvalidKeyMaterial("key file too short".into()));
    }
    let version = data[0];
    if version != FILE_VERSION {
        return Err(KeyProviderError::InvalidKeyMaterial(format!(
            "unsupported key file version {version}"
        )));
    }
    let algorithm = match data[1] {
        0 => SignatureAlgorithm::Ed25519,
        1 => SignatureAlgorithm::EcdsaSecp256k1,
        _ => return Err(KeyProviderError::InvalidKeyMaterial("unknown algorithm code".into())),
    };
    let nonce = data[2..26].to_vec();
    let salt = data[26..58].to_vec();
    let mem_cost = u32::from_le_bytes(data[58..62].try_into().unwrap());
    let time_cost = u32::from_le_bytes(data[62..66].try_into().unwrap());
    let parallelism = u32::from_le_bytes(data[66..70].try_into().unwrap());
    let ciphertext = data[70..].to_vec();

    Ok(EncryptedKeyExport {
        version,
        label: String::new(),
        algorithm,
        salt,
        nonce,
        ciphertext,
        kdf_params: KdfParams {
            mem_cost,
            time_cost,
            parallelism,
        },
    })
}

#[async_trait]
impl KeyProvider for FileEncryptedProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.ensure_unlocked().await?;
        let inner = {
            let state = self.unlocked.lock().unwrap();
            state
                .inner
                .clone()
                .ok_or(KeyProviderError::Locked)?
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

    async fn export_encrypted(&self, passphrase: &str) -> Result<EncryptedKeyExport> {
        let seed = {
            let state = self.unlocked.lock().unwrap();
            state
                .seed
                .clone()
                .ok_or(KeyProviderError::Locked)?
        };
        encrypt_seed(passphrase.as_bytes(), &seed, &self.label, self.algorithm)
    }
}

/// Factory that creates and manages encrypted key files in a directory.
///
/// Each key is stored as `<dir>/<label>.key`. A metadata file `<dir>/<label>.pub`
/// stores the public key so that `open()` can work without the passphrase.
pub struct FileEncryptedProviderFactory {
    dir: PathBuf,
    auto_lock_timeout: Duration,
}

impl FileEncryptedProviderFactory {
    pub fn new(dir: impl Into<PathBuf>, auto_lock_timeout: Duration) -> Self {
        Self {
            dir: dir.into(),
            auto_lock_timeout,
        }
    }

    /// Convenience constructor with a 5-minute auto-lock timeout.
    pub fn with_dir(dir: impl Into<PathBuf>) -> Self {
        Self::new(dir, Duration::from_secs(5 * 60))
    }

    fn key_path(&self, label: &str) -> PathBuf {
        self.dir.join(format!("{label}.key"))
    }

    fn pub_path(&self, label: &str) -> PathBuf {
        self.dir.join(format!("{label}.pub"))
    }
}

#[async_trait]
impl KeyProviderFactory for FileEncryptedProviderFactory {
    async fn create(
        &self,
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Arc<dyn KeyProvider>> {
        std::fs::create_dir_all(&self.dir)?;

        let key_path = self.key_path(label);
        if key_path.exists() {
            return Err(KeyProviderError::AlreadyExists(label.into()));
        }

        let passphrase = read_passphrase("Enter passphrase for new key: ")?;

        let provider = FileEncryptedProvider::create(
            label,
            key_path,
            algorithm,
            passphrase.as_bytes(),
            self.auto_lock_timeout,
        )?;

        // Persist the public key separately so open() works without passphrase.
        let pub_bytes = &provider.public_key().bytes;
        std::fs::write(self.pub_path(label), pub_bytes)?;

        Ok(Arc::new(provider))
    }

    async fn open(&self, label: &str) -> Result<Arc<dyn KeyProvider>> {
        let key_path = self.key_path(label);
        if !key_path.exists() {
            return Err(KeyProviderError::NotFound(label.into()));
        }

        // Read public key from sidecar file.
        let pub_path = self.pub_path(label);
        let pub_bytes = std::fs::read(&pub_path).unwrap_or_default();
        let export = read_key_file(&key_path)?;

        let provider = FileEncryptedProvider::open(label, key_path, self.auto_lock_timeout)?;

        // Patch in the real public key from sidecar.
        let mut provider = provider;
        if !pub_bytes.is_empty() {
            provider.public_data = PublicKeyData::new(export.algorithm, pub_bytes);
        }

        // Prompt for passphrase on first open.
        let passphrase = read_passphrase("Enter passphrase to unlock key: ")?;
        provider.unlock(passphrase.as_bytes()).await?;

        Ok(Arc::new(provider))
    }

    async fn list(&self) -> Result<Vec<String>> {
        if !self.dir.exists() {
            return Ok(vec![]);
        }
        let mut labels = vec![];
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("key") {
                if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                    labels.push(name.to_string());
                }
            }
        }
        labels.sort();
        Ok(labels)
    }

    async fn delete(&self, label: &str) -> Result<()> {
        let key_path = self.key_path(label);
        let pub_path = self.pub_path(label);
        if key_path.exists() {
            std::fs::remove_file(key_path)?;
        }
        if pub_path.exists() {
            std::fs::remove_file(pub_path)?;
        }
        Ok(())
    }
}

fn read_passphrase(_prompt: &str) -> Result<String> {
    #[cfg(feature = "rpassword")]
    {
        rpassword::read_password()
            .map_err(|e| KeyProviderError::AuthenticationFailed(format!("failed to read passphrase: {e}")))
    }
    #[cfg(not(feature = "rpassword"))]
    {
        let _ = prompt;
        Err(KeyProviderError::UnsupportedOperation(
            "enable 'rpassword' feature for interactive passphrase input".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn encrypted_file_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");
        let passphrase = b"correct-horse-battery-staple";

        let provider = FileEncryptedProvider::create(
            "test",
            path.clone(),
            SignatureAlgorithm::Ed25519,
            passphrase,
            Duration::from_secs(300),
        )
        .unwrap();

        let msg = b"hello encrypted world";
        let sig = provider.sign(msg).await.unwrap();
        assert_eq!(sig.len(), 64);

        // Reopen and unlock
        let reopened = FileEncryptedProvider::open("test", path, Duration::from_secs(300)).unwrap();
        reopened.unlock(passphrase).await.unwrap();
        let sig2 = reopened.sign(msg).await.unwrap();
        assert_eq!(sig, sig2);
    }

    #[tokio::test]
    async fn wrong_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.key");

        FileEncryptedProvider::create(
            "test",
            path.clone(),
            SignatureAlgorithm::Ed25519,
            b"good-passphrase",
            Duration::from_secs(300),
        )
        .unwrap();

        let reopened = FileEncryptedProvider::open("test", path, Duration::from_secs(300)).unwrap();
        let result = reopened.unlock(b"wrong-passphrase").await;
        assert!(result.is_err());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let seed = [42u8; 32];
        let export = encrypt_seed(b"passphrase", &seed, "test", SignatureAlgorithm::Ed25519).unwrap();
        let decrypted = decrypt_seed(b"passphrase", &export).unwrap();
        assert_eq!(decrypted.as_slice(), seed);
    }

    #[test]
    fn wrong_passphrase_decrypt_fails() {
        let seed = [42u8; 32];
        let export = encrypt_seed(b"passphrase", &seed, "test", SignatureAlgorithm::Ed25519).unwrap();
        assert!(decrypt_seed(b"wrong", &export).is_err());
    }
}
