//! Key generation helpers.
//!
//! These functions hide all cryptographic library details (`cesrox`,
//! `ed25519-dalek`, `rand`) so consumers never need to import those crates
//! directly.
//!
//! # Example
//!
//! ```no_run
//! use keri_sdk::keys;
//!
//! # fn example() -> keri_sdk::Result<()> {
//! let (seed, public_key) = keys::generate_ed25519()?;
//! println!("Public key: {:?}", public_key);
//! # Ok(())
//! # }
//! ```

use cesrox::primitives::codes::seed::SeedCode;
use keri_controller::BasicPrefix;
use keri_core::prefix::SeedPrefix;

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

/// Generate a random Ed25519 seed and derive its non-transferable public key.
///
/// Returns `(seed, public_key_prefix)`. The public key uses the
/// `Ed25519NT` (non-transferable) variant, which is the standard choice
/// for KERI next-key commitments.
///
/// # Errors
/// - [`Error::Signing`] if key derivation fails.
pub fn generate_ed25519() -> Result<(SeedPrefix, BasicPrefix)> {
    let seed = generate_ed25519_seed()?;
    let pk = derive_public_key(&seed)?;
    Ok((seed, pk))
}

/// Derive the non-transferable [`BasicPrefix`] from an existing seed.
///
/// # Errors
/// - [`Error::Signing`] if the seed cannot produce a key pair.
pub fn derive_public_key(seed: &SeedPrefix) -> Result<BasicPrefix> {
    let (pub_key, _) = seed
        .derive_key_pair()
        .map_err(|e| Error::Signing(e.to_string()))?;
    Ok(BasicPrefix::Ed25519NT(pub_key))
}
