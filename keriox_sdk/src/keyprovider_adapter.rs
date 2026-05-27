//! Adapter bridging [`keri_keyprovider::KeyProvider`] to the keriox signing interface.
//!
//! This module is only available when the `keyprovider` feature is enabled.
//!
//! [`KeriSigner`] wraps either a traditional [`Signer`] or a pluggable
//! [`KeyProvider`] and exposes a uniform sync `sign()` / `public_key()` API
//! that all SDK operations can use.

use std::sync::Arc;

use cesrox::primitives::codes::self_signing::SelfSigning;
use keri_controller::BasicPrefix;
use keri_core::{keys::PublicKey, signer::Signer};
use keri_keyprovider::SignatureAlgorithm;

use crate::error::Error;

/// Map a [`SignatureAlgorithm`] from the provider crate to the matching
/// CESR self-signing code.
pub(crate) fn signing_code_for(algorithm: SignatureAlgorithm) -> SelfSigning {
    match algorithm {
        SignatureAlgorithm::Ed25519 => SelfSigning::Ed25519Sha512,
        SignatureAlgorithm::EcdsaSecp256k1 => SelfSigning::ECDSAsecp256k1Sha256,
        SignatureAlgorithm::EcdsaSecp256r1 => SelfSigning::ECDSA256r1Sha256,
    }
}

/// Build a [`BasicPrefix`] of the right algorithm + transferability.
pub(crate) fn basic_prefix_for(
    algorithm: SignatureAlgorithm,
    public_key: PublicKey,
    transferable: bool,
) -> BasicPrefix {
    match (algorithm, transferable) {
        (SignatureAlgorithm::Ed25519, true) => BasicPrefix::Ed25519(public_key),
        (SignatureAlgorithm::Ed25519, false) => BasicPrefix::Ed25519NT(public_key),
        (SignatureAlgorithm::EcdsaSecp256k1, true) => BasicPrefix::ECDSAsecp256k1(public_key),
        (SignatureAlgorithm::EcdsaSecp256k1, false) => BasicPrefix::ECDSAsecp256k1NT(public_key),
        (SignatureAlgorithm::EcdsaSecp256r1, true) => BasicPrefix::ECDSA256r1(public_key),
        (SignatureAlgorithm::EcdsaSecp256r1, false) => BasicPrefix::ECDSA256r1NT(public_key),
    }
}

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
            KeriSigner::Legacy(s) => s.sign(msg).map_err(|e| Error::Signing(e.to_string())),
            KeriSigner::Provider(p) => {
                let msg = msg.to_vec();
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(async { p.sign(&msg).await })
                })
                .map_err(|e| Error::Signing(e.to_string()))
            }
        }
    }

    /// Return the public key as a keriox [`PublicKey`].
    pub fn public_key(&self) -> PublicKey {
        match self {
            KeriSigner::Legacy(s) => s.public_key(),
            KeriSigner::Provider(p) => PublicKey::new(p.public_key().bytes.clone()),
        }
    }

    /// Return the [`BasicPrefix`] for this key, in the variant matching the
    /// signer's algorithm.
    ///
    /// `transferable = true` returns the rotation-capable variant
    /// (Ed25519 / ECDSAsecp256k1 / ECDSA256r1); `false` returns the
    /// non-transferable variant.
    pub fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        let pk = self.public_key();
        match self {
            KeriSigner::Legacy(s) => s.basic_prefix(transferable),
            KeriSigner::Provider(p) => basic_prefix_for(p.algorithm(), pk, transferable),
        }
    }

    /// CESR self-signing code matching the signer's algorithm.
    pub fn signing_code(&self) -> SelfSigning {
        match self {
            KeriSigner::Legacy(s) => s.signing_code(),
            KeriSigner::Provider(p) => signing_code_for(p.algorithm()),
        }
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
