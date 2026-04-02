//! Adapter bridging [`keri_keyprovider::KeyProvider`] to the keriox signing interface.
//!
//! This module is only available when the `keyprovider` feature is enabled.
//!
//! [`KeriSigner`] wraps either a traditional [`Signer`] or a pluggable
//! [`KeyProvider`] and exposes a uniform sync `sign()` / `public_key()` API
//! that all SDK operations can use.

use std::sync::Arc;

use keri_core::{keys::PublicKey, signer::Signer};
use keri_controller::BasicPrefix;

use crate::error::Error;

/// Unified signer that works with either a legacy [`Signer`] or a
/// pluggable [`KeyProvider`](keri_keyprovider::KeyProvider).
///
/// Construct via the `From` implementations or the convenience constructors.
/// All SDK operations that previously took `Arc<Signer>` can now take `KeriSigner`.
#[derive(Clone)]
pub enum KeriSigner {
    /// Legacy in-memory signer (keriox_core::Signer).
    Legacy(Arc<Signer>),
    /// Pluggable key provider (keri_keyprovider::KeyProvider).
    Provider(Arc<dyn keri_keyprovider::KeyProvider>),
}

impl KeriSigner {
    /// Sign a message, returning raw Ed25519 signature bytes.
    ///
    /// For the `Legacy` variant this delegates to [`Signer::sign()`].
    /// For the `Provider` variant it blocks on the async
    /// [`KeyProvider::sign()`](keri_keyprovider::KeyProvider::sign) call
    /// (the call is CPU-bound and completes immediately for software keys).
    pub fn sign(&self, msg: &[u8]) -> crate::Result<Vec<u8>> {
        match self {
            KeriSigner::Legacy(s) => s
                .sign(msg)
                .map_err(|e| Error::Signing(e.to_string())),
            KeriSigner::Provider(p) => {
                let msg = msg.to_vec();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async {
                        p.sign(&msg).await
                    })
                })
                .map_err(|e| Error::Signing(e.to_string()))
            }
        }
    }

    /// Return the public key as a keriox [`PublicKey`].
    pub fn public_key(&self) -> PublicKey {
        match self {
            KeriSigner::Legacy(s) => s.public_key(),
            KeriSigner::Provider(p) => {
                PublicKey::new(p.public_key().bytes.clone())
            }
        }
    }

    /// Return the [`BasicPrefix::Ed25519`] for this key (transferable).
    pub fn basic_prefix(&self) -> BasicPrefix {
        BasicPrefix::Ed25519(self.public_key())
    }

    /// Return the [`BasicPrefix::Ed25519NT`] for this key (non-transferable).
    pub fn basic_prefix_nt(&self) -> BasicPrefix {
        BasicPrefix::Ed25519NT(self.public_key())
    }
}

impl From<Arc<Signer>> for KeriSigner {
    fn from(signer: Arc<Signer>) -> Self {
        KeriSigner::Legacy(signer)
    }
}

impl From<Arc<dyn keri_keyprovider::KeyProvider>> for KeriSigner {
    fn from(provider: Arc<dyn keri_keyprovider::KeyProvider>) -> Self {
        KeriSigner::Provider(provider)
    }
}
