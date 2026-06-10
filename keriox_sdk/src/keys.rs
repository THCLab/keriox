//! Key generation helpers.
//!
//! These functions hide all cryptographic library details (`cesrox`,
//! `ed25519-dalek`, `p256`, `k256`, `rand`) so consumers never need to
//! import those crates directly.
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
use keri_core::{
    prefix::{self, SeedPrefix},
    signer::SignerAlgorithm,
};

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

/// Generate a random secp256k1 (Bitcoin curve) seed.
///
/// # Errors
/// - [`Error::Signing`] if entropy generation fails.
pub fn generate_secp256k1_seed() -> Result<SeedPrefix> {
    use rand::rngs::OsRng;

    let sk = k256::ecdsa::SigningKey::random(&mut OsRng);
    Ok(SeedPrefix::new(
        SeedCode::RandomSeed256ECDSAsecp256k1,
        sk.to_bytes().to_vec(),
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

/// Generate a random seed for the requested algorithm.
///
/// Convenience dispatcher used by higher-level entry points like
/// [`KeriStore::create`](crate::store::KeriStore::create) that need to
/// generate a seed without committing to a specific curve at compile time.
///
/// # Errors
/// - [`Error::Signing`] if entropy generation fails.
pub fn generate_seed(algorithm: SignerAlgorithm) -> Result<SeedPrefix> {
    match algorithm {
        SignerAlgorithm::Ed25519 => generate_ed25519_seed(),
        SignerAlgorithm::EcdsaSecp256k1 => generate_secp256k1_seed(),
        SignerAlgorithm::EcdsaSecp256r1 => generate_p256_seed(),
    }
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

/// Generate a random secp256k1 seed and derive its public key.
///
/// See [`generate_ed25519`] for the transferability contract.
///
/// # Errors
/// - [`Error::Signing`] if key derivation fails.
pub fn generate_secp256k1(transferable: bool) -> Result<(SeedPrefix, BasicPrefix)> {
    let seed = generate_secp256k1_seed()?;
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

/// Generate a fresh `(seed, public_key)` pair for the requested algorithm
/// and transferability.
///
/// # Errors
/// - [`Error::Signing`] if entropy generation or key derivation fails.
pub fn generate_keypair(
    algorithm: SignerAlgorithm,
    transferable: bool,
) -> Result<(SeedPrefix, BasicPrefix)> {
    let seed = generate_seed(algorithm)?;
    let pk = derive_public_key(&seed, transferable)?;
    Ok((seed, pk))
}

/// Build a [`SeedPrefix`] from a CESR seed code and raw secret key bytes.
///
/// `code` is the CESR derivation code for the seed algorithm (e.g. `"A"`
/// for a 256-bit Ed25519 seed, `"J"` for secp256k1, `"Q"` for P-256). The
/// seed is validated by deriving its key pair before being returned.
///
/// # Errors
/// - [`Error::ParseError`] if `code` is not a valid CESR seed code.
/// - [`Error::Signing`] if the secret key bytes cannot produce a key pair.
pub fn seed_from_code(code: &str, secret_key: Vec<u8>) -> Result<SeedPrefix> {
    let code: SeedCode = code
        .parse()
        .map_err(|_| Error::ParseError(format!("invalid seed code: {code}")))?;
    let seed = SeedPrefix::new(code, secret_key);
    seed.derive_key_pair()
        .map_err(|e| Error::Signing(e.to_string()))?;
    Ok(seed)
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

/// Infer the [`SignerAlgorithm`] associated with a [`SeedPrefix`].
///
/// Useful when you load a seed from disk and need to generate a matching
/// new seed (e.g. for the next-key during rotation).
///
/// # Errors
/// - [`Error::Signing`] if the seed variant is not supported by [`Signer`].
pub fn seed_algorithm(seed: &SeedPrefix) -> Result<SignerAlgorithm> {
    match seed {
        SeedPrefix::RandomSeed256Ed25519(_) => Ok(SignerAlgorithm::Ed25519),
        SeedPrefix::RandomSeed256ECDSAsecp256k1(_) => Ok(SignerAlgorithm::EcdsaSecp256k1),
        SeedPrefix::RandomSeed256ECDSA256r1(_) => Ok(SignerAlgorithm::EcdsaSecp256r1),
        SeedPrefix::RandomSeed448(_) => Err(Error::Signing(
            "Ed448 seeds are not yet supported by Signer".into(),
        )),
    }
}
