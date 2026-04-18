//! Error types for the keri-sdk crate.
//!
//! All public functions in this crate return [`Result<T>`], which is an alias
//! for `std::result::Result<T, Error>`. Import the alias with
//! `use keri_sdk::Result;` or use it fully-qualified as `keri_sdk::Result<T>`.
//!
//! Most variants carry enough context to identify the failing operation without
//! needing to inspect the wrapped upstream error. Where an upstream error is
//! propagated transparently it is wrapped in one of the `Controller`,
//! `Mechanics`, or `Signing` variants.

use keri_controller::IdentifierPrefix;
use keri_core::actor::prelude::SelfAddressingIdentifier;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    // ── Transparent upstream wrappers ─────────────────────────────────────────
    /// Wraps errors from the `keri-controller` layer.
    #[error(transparent)]
    Controller(#[from] keri_controller::error::ControllerError),

    /// Wraps errors from the identifier mechanics layer.
    #[error(transparent)]
    Mechanics(#[from] keri_controller::identifier::mechanics::MechanicsError),

    /// Wraps key-signing errors.
    #[error("signing error: {0}")]
    Signing(String),

    // ── Specific actionable variants ──────────────────────────────────────────
    /// The requested identifier is not known to this controller.
    #[error("identifier not found: {0}")]
    IdentifierNotFound(IdentifierPrefix),

    /// The identifier has no watchers configured.
    #[error("no watchers configured for identifier: {0}")]
    NoWatchers(IdentifierPrefix),

    /// The identifier has no witnesses configured.
    #[error("no witnesses configured for identifier: {0}")]
    NoWitnesses(IdentifierPrefix),

    /// A credential registry has not been incepted for this identifier.
    #[error("registry not incepted for identifier: {0}")]
    RegistryNotIncepted(IdentifierPrefix),

    /// The credential is not known in the local TEL.
    #[error("credential not found in TEL: {0}")]
    CredentialNotFound(SelfAddressingIdentifier),

    /// Signature verification failed.
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Missing KEL event for the given identifier — OOBI may need to be resolved first.
    #[error("missing KEL event for {id}")]
    MissingKelEvent {
        id: IdentifierPrefix,
        event_sai: Option<SelfAddressingIdentifier>,
    },

    /// CESR stream could not be parsed.
    #[error("CESR parse error: {0}")]
    CesrParseError(String),

    /// A CESR / CBOR / JSON encoding step failed.
    #[error("encoding error: {0}")]
    EncodingError(String),

    /// A disk I/O or database persistence error.
    #[error("persistence error: {0}")]
    PersistenceError(String),

    /// OOBI resolution failed for a specific identifier.
    #[error("OOBI resolution failed for {id}: {reason}")]
    OobiResolutionFailed {
        /// The identifier whose OOBI could not be resolved.
        id: IdentifierPrefix,
        /// A human-readable description of what went wrong.
        reason: String,
    },

    /// No pending delegation request was found in the mailbox.
    #[error("no delegation request found")]
    NoDelegationRequest,

    /// A delegation-specific error.
    #[error("delegation error: {0}")]
    DelegationError(String),

    /// No pending multisig request was found in the mailbox.
    #[error("no multisig request found")]
    NoMultisigRequest,

    /// A multisig-specific error.
    #[error("multisig error: {0}")]
    MultisigError(String),

    /// The delegator's key event log is not available locally.
    /// Resolve the delegator's OOBI before calling `complete_delegation`.
    #[error("delegator KEL not available locally for {0}; resolve the delegator's OOBI first")]
    DelegatorKelNotAvailable(IdentifierPrefix),

    /// Failed to parse a string as an identifier prefix or SAID.
    #[error("failed to parse identifier or SAID: {0}")]
    ParseError(String),

    /// A catch-all for errors that do not fit a more specific variant.
    #[error("{0}")]
    Other(String),
}

impl From<keri_core::processor::validator::VerificationError> for Error {
    fn from(e: keri_core::processor::validator::VerificationError) -> Self {
        Error::VerificationFailed(e.to_string())
    }
}

impl From<keri_core::error::Error> for Error {
    fn from(e: keri_core::error::Error) -> Self {
        Error::VerificationFailed(e.to_string())
    }
}

/// Convenience alias — all SDK functions return this type.
pub type Result<T> = std::result::Result<T, Error>;
