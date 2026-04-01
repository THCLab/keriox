//! Typed config structs and result types for keri-sdk operations.
//!
//! These structs replace long positional argument lists throughout the SDK.
//! Import them with `use keri_sdk::*` (they are re-exported from the crate
//! root) or qualify them as `keri_sdk::IdentifierConfig` etc.
//!
//! See [`crate::operations`] for the functions that accept these structs, and
//! [`crate::signing`] for `SignedEnvelope` / `VerifiedPayload` usage.

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme};

// ── Creation / rotation config ────────────────────────────────────────────────

/// Configuration for creating a new KERI identifier.
///
/// Used by [`crate::operations::create_identifier`] and
/// [`crate::store::KeriStore::create`].
#[derive(Debug, Default, Clone)]
pub struct IdentifierConfig {
    /// Witness OOBIs to include in the inception event.
    pub witnesses: Vec<LocationScheme>,
    /// Signing threshold required for witness receipts.
    pub witness_threshold: u64,
    /// Watcher OOBIs to configure after inception.
    pub watchers: Vec<LocationScheme>,
}

/// Configuration for rotating an identifier's keys.
///
/// Used by [`crate::operations::rotate`].
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// The new *next* (pre-rotated) public key.
    pub new_next_pk: BasicPrefix,
    /// Witnesses to add during this rotation.
    pub witness_to_add: Vec<LocationScheme>,
    /// Witnesses to remove during this rotation.
    pub witness_to_remove: Vec<BasicPrefix>,
    /// New witness signing threshold (0 = keep current).
    pub witness_threshold: u64,
}

// ── Signing / verification result types ──────────────────────────────────────

/// A CESR-encoded signed payload ready for transport.
///
/// Returned by [`crate::signing::sign`] and [`crate::signing::sign_json`].
#[derive(Debug, Clone)]
pub struct SignedEnvelope {
    /// The raw payload bytes that were signed.
    pub payload: Vec<u8>,
    /// Full CESR stream: payload text + attached transferable signatures.
    /// This string is what you send over the wire.
    pub cesr: String,
}

/// The verified contents of a CESR-signed envelope.
///
/// Returned by [`crate::signing::verify`] on success.
#[derive(Debug, Clone)]
pub struct VerifiedPayload {
    /// The raw payload bytes extracted from the CESR stream.
    pub payload: Vec<u8>,
    /// The identifier that produced the signature.
    pub signer_id: IdentifierPrefix,
}

// ── TEL credential status ─────────────────────────────────────────────────────

/// The current lifecycle state of a credential in the TEL.
///
/// Returned by [`crate::tel::get_credential_status`] and
/// [`crate::tel::check_credential_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential has been issued and is currently valid.
    Issued,
    /// The credential has been revoked.
    Revoked,
    /// The TEL has not been queried yet, or the credential is not known locally.
    Unknown,
}
