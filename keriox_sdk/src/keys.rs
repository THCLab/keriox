//! Key generation helpers.
//!
//! These functions hide all cryptographic library details (`cesrox`,
//! `ed25519-dalek`, `p256`, `rand`) so consumers never need to import those
//! crates directly.
//!
//! # Example
//!
//! ```no_run
//! use keri_sdk::keys;
//!
//! # fn example() -> keri_sdk::Result<()> {
//! // Generate a transferable Ed25519 key pair for an AID that can rotate.
//! let (seed, public_key) = keys::generate_ed25519(true)?;
//! println!("Public key: {:?}", public_key);
//! # Ok(())
//! # }
//! ```

use cesrox::primitives::codes::seed::SeedCode;
use keri_controller::BasicPrefix;
use keri_core::prefix::{self, SeedPrefix};

use crate::error::{Error, Result};

/// Generate a random Ed25519 seed.
///
/// The returned [`SeedPrefix`] can be used with
/// [`KeriStore::create_with_seeds`](crate::store::KeriStore::create_with_seeds)
/// or [`derive_public_key`] to obtain the corresponding public key.
///
/// # Errors
/// - [`Error::Signing`] if entropy generation fails.
pub fn generate_ed25519_seed() -> Result<SeedPrefix> {
    use rand::rngs::OsRng;

    let ed_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
    Ok(SeedPrefix::new(
        SeedCode::RandomSeed256Ed25519,
        ed_key.as_bytes().to_vec(),
    ))
}

/// Generate a random P-256 (NIST secp256r1) seed.
///
/// This is the curve natively supported by iOS Secure Enclave and Android
/// Keystore, so it is the right choice for KERI identifiers whose signing
/// key is expected to live in mobile platform crypto.
///
/// # Errors
/// - [`Error::Signing`] if entropy generation fails.
pub fn generate_p256_seed() -> Result<SeedPrefix> {
    use rand::rngs::OsRng;

    let sk = p256::ecdsa::SigningKey::random(&mut OsRng);
    Ok(SeedPrefix::new(
        SeedCode::RandomSeed256ECDSA256r1,
        sk.to_bytes().to_vec(),
    ))
}

/// Generate a random Ed25519 seed and derive its public key.
///
/// `transferable = true` returns a [`BasicPrefix::Ed25519`] suitable for
/// controlling a KERI AID that can rotate. `transferable = false` returns
/// [`BasicPrefix::Ed25519NT`], where the public key permanently *is* the
/// identifier — used for witnesses, watchers, and next-key commitments.
///
/// # Errors
/// - [`Error::Signing`] if key derivation fails.
pub fn generate_ed25519(transferable: bool) -> Result<(SeedPrefix, BasicPrefix)> {
    let seed = generate_ed25519_seed()?;
    let pk = derive_public_key(&seed, transferable)?;
    Ok((seed, pk))
}

/// Generate a random P-256 seed and derive its public key.
///
/// See [`generate_ed25519`] for the transferability contract.
///
/// # Errors
/// - [`Error::Signing`] if key derivation fails.
pub fn generate_p256(transferable: bool) -> Result<(SeedPrefix, BasicPrefix)> {
    let seed = generate_p256_seed()?;
    let pk = derive_public_key(&seed, transferable)?;
    Ok((seed, pk))
}

/// Derive the [`BasicPrefix`] from an existing seed.
///
/// `transferable = true` selects the rotation-capable variant
/// (`Ed25519`, `ECDSAsecp256k1`, `ECDSA256r1`); `false` selects the
/// non-transferable variant (`Ed25519NT`, `ECDSAsecp256k1NT`,
/// `ECDSA256r1NT`).
///
/// # Errors
/// - [`Error::Signing`] if the seed cannot produce a key pair, or if the
///   seed variant is not yet wired into [`prefix::derive`].
pub fn derive_public_key(seed: &SeedPrefix, transferable: bool) -> Result<BasicPrefix> {
    prefix::derive(seed, transferable).map_err(|e| Error::Signing(e.to_string()))
}
