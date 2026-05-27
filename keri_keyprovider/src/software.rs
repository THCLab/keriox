//! In-memory software key provider using ed25519-dalek, k256, and p256.

use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;

use crate::{
    KeyProvider, KeyProviderError, KeyProviderFactory, PublicKeyData, Result, SignatureAlgorithm,
};

/// In-memory Ed25519, secp256k1, or P-256 signing key.
///
/// Private key material lives only in RAM. The inner signing keys handle their
/// own cleanup when dropped. Public key bytes are not zeroized since they
/// are not secret.
pub struct SoftwareKeyProvider {
    label: String,
    inner: SoftwareKeyInner,
    public_data: PublicKeyData,
}

enum SoftwareKeyInner {
    Ed25519(ed25519_dalek::SigningKey),
    Secp256k1(k256::ecdsa::SigningKey),
    P256(p256::ecdsa::SigningKey),
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
            SignatureAlgorithm::EcdsaSecp256r1 => {
                let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
                let vk = p256::ecdsa::VerifyingKey::from(&sk);
                let pk_bytes = vk.to_encoded_point(true).as_bytes().to_vec();
                Ok(Self {
                    label: label.into(),
                    inner: SoftwareKeyInner::P256(sk),
                    public_data: PublicKeyData::secp256r1(pk_bytes),
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

    pub fn from_secp256k1_bytes(label: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let sk = k256::ecdsa::SigningKey::from_bytes(seed)
            .map_err(|e| KeyProviderError::InvalidKeyMaterial(format!("secp256k1 seed: {e}")))?;
        let pk_bytes = sk.verifying_key().to_bytes().to_vec();
        Ok(Self {
            label: label.into(),
            inner: SoftwareKeyInner::Secp256k1(sk),
            public_data: PublicKeyData::secp256k1(pk_bytes),
        })
    }

    pub fn from_p256_bytes(label: impl Into<String>, seed: &[u8]) -> Result<Self> {
        let sk = p256::ecdsa::SigningKey::from_bytes(seed)
            .map_err(|e| KeyProviderError::InvalidKeyMaterial(format!("P-256 seed: {e}")))?;
        let vk = p256::ecdsa::VerifyingKey::from(&sk);
        let pk_bytes = vk.to_encoded_point(true).as_bytes().to_vec();
        Ok(Self {
            label: label.into(),
            inner: SoftwareKeyInner::P256(sk),
            public_data: PublicKeyData::secp256r1(pk_bytes),
        })
    }

    /// Return the raw seed bytes for any in-memory algorithm.
    ///
    /// Returns 32 bytes for all currently supported algorithms (Ed25519
    /// seed, secp256k1 scalar, P-256 scalar).
    pub fn seed_bytes(&self) -> Vec<u8> {
        match &self.inner {
            SoftwareKeyInner::Ed25519(sk) => sk.to_bytes().to_vec(),
            SoftwareKeyInner::Secp256k1(sk) => sk.to_bytes().to_vec(),
            SoftwareKeyInner::P256(sk) => sk.to_bytes().to_vec(),
        }
    }

    pub fn ed25519_seed_bytes(&self) -> Option<[u8; 32]> {
        match &self.inner {
            SoftwareKeyInner::Ed25519(sk) => Some(sk.to_bytes()),
            _ => None,
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
                // KERI's 0C self-signing code requires raw 64-byte r||s,
                // not DER. Use as_ref() instead of to_der().
                Ok(sig.as_ref().to_vec())
            }
            SoftwareKeyInner::P256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk.sign(message);
                Ok(sig.as_ref().to_vec())
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
        let pk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap())
            .unwrap();
        let signature = ed25519_dalek::Signature::from_bytes(sig.as_slice().try_into().unwrap());
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
        let p1 = factory
            .create("a", SignatureAlgorithm::Ed25519)
            .await
            .unwrap();
        let p2 = factory
            .create("b", SignatureAlgorithm::Ed25519)
            .await
            .unwrap();
        assert_ne!(p1.public_key().bytes, p2.public_key().bytes);
    }

    #[tokio::test]
    async fn factory_open_returns_not_found() {
        let factory = SoftwareKeyProviderFactory;
        assert!(factory.open("anything").await.is_err());
    }

    #[tokio::test]
    async fn secp256k1_sign_is_raw_64_bytes() {
        // Regression: KERI's 0C self-signing code requires raw r||s,
        // not DER. DER would be variable-length (~70-72 bytes).
        let provider =
            SoftwareKeyProvider::generate("test", SignatureAlgorithm::EcdsaSecp256k1).unwrap();
        let sig = provider.sign(b"hello").await.unwrap();
        assert_eq!(sig.len(), 64, "secp256k1 must emit raw r||s for KERI 0C");
    }

    #[tokio::test]
    async fn p256_sign_verify_roundtrip() {
        use p256::ecdsa::{
            signature::Verifier as _, Signature, VerifyingKey,
        };

        let provider =
            SoftwareKeyProvider::generate("test", SignatureAlgorithm::EcdsaSecp256r1).unwrap();
        let msg = b"native curve mobile";
        let sig = provider.sign(msg).await.unwrap();
        assert_eq!(sig.len(), 64, "P-256 must emit raw r||s for KERI 0I");

        let pk_bytes = &provider.public_key().bytes;
        let vk = VerifyingKey::from_sec1_bytes(pk_bytes).unwrap();
        let signature = Signature::try_from(sig.as_slice()).unwrap();
        assert!(vk.verify(msg, &signature).is_ok());
    }
}
