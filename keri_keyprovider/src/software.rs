//! In-memory software key provider using ed25519-dalek and k256.

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use crate::{
    KeyProvider, KeyProviderError, KeyProviderFactory,
    PublicKeyData, Result, SignatureAlgorithm,
};

/// In-memory Ed25519 or secp256k1 signing key.
///
/// Private key material lives only in RAM. The inner signing keys
/// (`ed25519_dalek::SigningKey`, `k256::ecdsa::SigningKey`) handle their
/// own cleanup when dropped. Public key bytes are not zeroized since they
/// are not secret.
pub struct SoftwareKeyProvider {
    label: String,
    inner: SoftwareKeyInner,
    public_data: PublicKeyData,
}

enum SoftwareKeyInner {
    Ed25519(ed25519_dalek::SigningKey),
    #[allow(dead_code)]
    Secp256k1(k256::ecdsa::SigningKey),
}

impl SoftwareKeyProvider {
    pub fn generate(label: impl Into<String>, algorithm: SignatureAlgorithm) -> Result<Self> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
                let pk_bytes = sk.verifying_key().to_bytes().to_vec();
                Ok(Self {
                    label: label.into(),
                    inner: SoftwareKeyInner::Ed25519(sk),
                    public_data: PublicKeyData::ed25519(pk_bytes),
                })
            }
            SignatureAlgorithm::EcdsaSecp256k1 => {
                let sk = k256::ecdsa::SigningKey::random(&mut OsRng);
                let pk_bytes = sk.verifying_key().to_bytes().to_vec();
                Ok(Self {
                    label: label.into(),
                    inner: SoftwareKeyInner::Secp256k1(sk),
                    public_data: PublicKeyData::secp256k1(pk_bytes),
                })
            }
        }
    }

    pub fn from_ed25519_bytes(label: impl Into<String>, seed: &[u8; 32]) -> Result<Self> {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed);
        let pk_bytes = sk.verifying_key().to_bytes().to_vec();
        Ok(Self {
            label: label.into(),
            inner: SoftwareKeyInner::Ed25519(sk),
            public_data: PublicKeyData::ed25519(pk_bytes),
        })
    }

    pub fn ed25519_seed_bytes(&self) -> Option<[u8; 32]> {
        match &self.inner {
            SoftwareKeyInner::Ed25519(sk) => Some(sk.to_bytes()),
            SoftwareKeyInner::Secp256k1(_) => None,
        }
    }
}

#[async_trait]
impl KeyProvider for SoftwareKeyProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        match &self.inner {
            SoftwareKeyInner::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                let sig: ed25519_dalek::Signature = sk.sign(message);
                Ok(sig.to_bytes().to_vec())
            }
            SoftwareKeyInner::Secp256k1(sk) => {
                use k256::ecdsa::signature::Signer as _;
                let sig: k256::ecdsa::Signature = sk.sign(message);
                Ok(sig.to_der().as_bytes().to_vec())
            }
        }
    }

    fn public_key(&self) -> &PublicKeyData {
        &self.public_data
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn supports_rotation(&self) -> bool {
        true
    }

    async fn rotate(&mut self, _new_next_public_key: PublicKeyData) -> Result<()> {
        let new = Self::generate(self.label.clone(), self.algorithm())?;
        // Safe: no Drop impl on Self, so moving fields is fine.
        // The old inner value (with old private key) is dropped naturally.
        self.inner = new.inner;
        self.public_data = new.public_data;
        Ok(())
    }

    fn supports_export(&self) -> bool {
        true
    }
}

/// Stateless factory that creates in-memory keys.
///
/// Since software keys are ephemeral, `open()` always returns `NotFound`.
/// Use `FileEncryptedProviderFactory` or `OsKeychainProviderFactory` for
/// persistent backends.
pub struct SoftwareKeyProviderFactory;

#[async_trait]
impl KeyProviderFactory for SoftwareKeyProviderFactory {
    async fn create(
        &self,
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Arc<dyn KeyProvider>> {
        Ok(Arc::new(SoftwareKeyProvider::generate(label, algorithm)?))
    }

    async fn open(&self, label: &str) -> Result<Arc<dyn KeyProvider>> {
        Err(KeyProviderError::NotFound(format!(
            "software provider is stateless; key '{label}' was not created in this session"
        )))
    }

    async fn list(&self) -> Result<Vec<String>> {
        Ok(vec![])
    }

    async fn delete(&self, _label: &str) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    #[tokio::test]
    async fn ed25519_sign_verify_roundtrip() {
        let provider = SoftwareKeyProvider::generate("test", SignatureAlgorithm::Ed25519).unwrap();
        let msg = b"hello keri";
        let sig = provider.sign(msg).await.unwrap();
        assert_eq!(sig.len(), 64);

        let pk_bytes = &provider.public_key().bytes;
        let pk = ed25519_dalek::VerifyingKey::from_bytes(
            pk_bytes.as_slice().try_into().unwrap(),
        )
        .unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(
            sig.as_slice().try_into().unwrap(),
        );
        assert!(pk.verify(msg, &signature).is_ok());
    }

    #[tokio::test]
    async fn from_seed_reproduces_same_key() {
        let seed = [42u8; 32];
        let p1 = SoftwareKeyProvider::from_ed25519_bytes("a", &seed).unwrap();
        let p2 = SoftwareKeyProvider::from_ed25519_bytes("b", &seed).unwrap();
        assert_eq!(p1.public_key().bytes, p2.public_key().bytes);
    }

    #[tokio::test]
    async fn factory_creates_unique_keys() {
        let factory = SoftwareKeyProviderFactory;
        let p1 = factory.create("a", SignatureAlgorithm::Ed25519).await.unwrap();
        let p2 = factory.create("b", SignatureAlgorithm::Ed25519).await.unwrap();
        assert_ne!(p1.public_key().bytes, p2.public_key().bytes);
    }

    #[tokio::test]
    async fn factory_open_returns_not_found() {
        let factory = SoftwareKeyProviderFactory;
        assert!(factory.open("anything").await.is_err());
    }
}
