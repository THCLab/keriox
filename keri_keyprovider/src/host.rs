//! Host-callback key provider for mobile environments.
//!
//! This module provides [`HostCallbackKeyProvider`] and
//! [`HostKeyProviderFactory`] — a key provider implementation that delegates
//! all cryptographic operations (key generation, signing) to **callbacks**
//! registered by the host platform (Android / iOS).
//!
//! The private key **never** enters the Rust address space. The host platform
//! is responsible for storing keys in its native keystore (Android Keystore,
//! iOS Keychain / Secure Enclave) and performing signing operations there.

use std::sync::Arc;

use async_trait::async_trait;

use crate::{
    KeyProvider, KeyProviderError, KeyProviderFactory, PublicKeyData,
    Result, SignatureAlgorithm,
};

type SignCallback =
    Arc<dyn Fn(&str, &[u8]) -> Result<Vec<u8>> + Send + Sync>;
type PublicKeyCallback =
    Arc<dyn Fn(&str) -> Result<PublicKeyData> + Send + Sync>;
type CreateKeyCallback =
    Arc<dyn Fn(&str, SignatureAlgorithm) -> Result<PublicKeyData> + Send + Sync>;
type DeleteKeyCallback =
    Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;
type ListKeysCallback =
    Arc<dyn Fn() -> Result<Vec<String>> + Send + Sync>;

/// Key provider that delegates signing to a host platform callback.
///
/// The host (Dart/Swift/Kotlin) registers callbacks at initialisation time.
/// When the SDK needs to sign, it invokes the `sign` callback which triggers
/// a platform keystore operation (possibly including a biometric prompt).
pub struct HostCallbackKeyProvider {
    label: String,
    public_data: PublicKeyData,
    sign_fn: SignCallback,
}

impl HostCallbackKeyProvider {
    pub fn new(
        label: impl Into<String>,
        public_data: PublicKeyData,
        sign_fn: SignCallback,
    ) -> Self {
        Self {
            label: label.into(),
            public_data,
            sign_fn,
        }
    }
}

#[async_trait]
impl KeyProvider for HostCallbackKeyProvider {
    async fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        (self.sign_fn)(self.label(), message)
    }

    fn public_key(&self) -> &PublicKeyData {
        &self.public_data
    }

    fn label(&self) -> &str {
        &self.label
    }

    fn supports_export(&self) -> bool {
        false
    }
}

/// Factory that creates [`HostCallbackKeyProvider`]s by calling host callbacks.
///
/// Register one per SDK instance. The callbacks must be safe to call from
/// any thread (they are wrapped in `Arc<dyn Fn … + Send + Sync>`).
pub struct HostKeyProviderFactory {
    create_fn: CreateKeyCallback,
    open_fn: PublicKeyCallback,
    sign_fn: SignCallback,
    delete_fn: DeleteKeyCallback,
    list_fn: ListKeysCallback,
}

impl HostKeyProviderFactory {
    pub fn new(
        create_fn: impl Fn(&str, SignatureAlgorithm) -> Result<PublicKeyData> + Send + Sync + 'static,
        open_fn: impl Fn(&str) -> Result<PublicKeyData> + Send + Sync + 'static,
        sign_fn: impl Fn(&str, &[u8]) -> Result<Vec<u8>> + Send + Sync + 'static,
        delete_fn: impl Fn(&str) -> Result<()> + Send + Sync + 'static,
        list_fn: impl Fn() -> Result<Vec<String>> + Send + Sync + 'static,
    ) -> Self {
        Self {
            create_fn: Arc::new(create_fn),
            open_fn: Arc::new(open_fn),
            sign_fn: Arc::new(sign_fn),
            delete_fn: Arc::new(delete_fn),
            list_fn: Arc::new(list_fn),
        }
    }
}

#[async_trait]
impl KeyProviderFactory for HostKeyProviderFactory {
    async fn create(
        &self,
        label: &str,
        algorithm: SignatureAlgorithm,
    ) -> Result<Arc<dyn KeyProvider>> {
        let public_data = (self.create_fn)(label, algorithm)?;
        let sign_fn = self.sign_fn.clone();
        Ok(Arc::new(HostCallbackKeyProvider::new(label, public_data, sign_fn)))
    }

    async fn open(&self, label: &str) -> Result<Arc<dyn KeyProvider>> {
        let public_data = (self.open_fn)(label)?;
        let sign_fn = self.sign_fn.clone();
        Ok(Arc::new(HostCallbackKeyProvider::new(label, public_data, sign_fn)))
    }

    async fn list(&self) -> Result<Vec<String>> {
        (self.list_fn)()
    }

    async fn delete(&self, label: &str) -> Result<()> {
        (self.delete_fn)(label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct InMemoryStore {
        keys: Vec<(String, PublicKeyData)>,
    }

    #[tokio::test]
    async fn factory_create_and_sign() {
        let store = Arc::new(Mutex::new(InMemoryStore { keys: vec![] }));
        let store_clone = store.clone();

        let create_fn = move |label: &str, algo: SignatureAlgorithm| {
            let pk = PublicKeyData::new(algo, vec![1u8; 32]);
            store_clone.lock().unwrap().keys.push((label.to_string(), pk.clone()));
            Ok(pk)
        };

        let store_clone = store.clone();
        let open_fn = move |label: &str| {
            store_clone
                .lock()
                .unwrap()
                .keys
                .iter()
                .find(|(l, _)| l == label)
                .map(|(_, pk)| pk.clone())
                .ok_or_else(|| KeyProviderError::NotFound(label.to_string()))
        };

        let sign_fn = |label: &str, msg: &[u8]| {
            let _ = label;
            Ok(vec![0u8; 64])
        };

        let store_clone = store.clone();
        let delete_fn = move |label: &str| {
            store_clone.lock().unwrap().keys.retain(|(l, _)| l != label);
            Ok(())
        };

        let store_clone = store.clone();
        let list_fn = move || {
            Ok(store_clone
                .lock()
                .unwrap()
                .keys
                .iter()
                .map(|(l, _)| l.clone())
                .collect())
        };

        let factory = HostKeyProviderFactory::new(create_fn, open_fn, sign_fn, delete_fn, list_fn);

        let provider = factory.create("test-key", SignatureAlgorithm::Ed25519).await.unwrap();
        assert_eq!(provider.label(), "test-key");
        assert_eq!(provider.public_key().bytes, vec![1u8; 32]);

        let sig = provider.sign(b"hello").await.unwrap();
        assert_eq!(sig.len(), 64);

        let keys = factory.list().await.unwrap();
        assert_eq!(keys, vec!["test-key"]);

        let opened = factory.open("test-key").await.unwrap();
        assert_eq!(opened.label(), "test-key");

        factory.delete("test-key").await.unwrap();
        assert!(factory.list().await.unwrap().is_empty());
    }
}
