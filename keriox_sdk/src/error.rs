//! The error type returned by the high-level API.
//!
//! Every variant's message states what happened **and** what to do next, so
//! errors can be shown to developers (or logged) without a KERI background.
//! Lower-level failures that have no friendly mapping are passed through as
//! [`Error::Advanced`].

use std::path::PathBuf;

use crate::ids::{CredentialId, IdentityId};

/// The error type of the high-level API.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The alias is not present in this store.
    #[error("identity '{0}' not found in this store; create it with Keri::new_identity(\"{0}\")")]
    IdentityNotFound(String),

    /// The alias is already taken in this store.
    #[error("identity '{0}' already exists; load it with Keri::identity(\"{0}\")")]
    IdentityExists(String),

    /// A signature was made by an identity whose history is not known locally.
    #[error("unknown signer {id}; import their identity first: keri.import_contact(\"<their witness or OOBI URL>\").await")]
    UnknownSigner {
        /// The identity that produced the signature.
        id: IdentityId,
    },

    /// The signature did not verify against the signer's known keys.
    #[error("signature check failed: the message was not signed by {claimed} with their current keys (it may be forged, altered, or signed before a key rotation)")]
    InvalidSignature {
        /// The identity the message claims as its signer.
        claimed: IdentityId,
    },

    /// A witness could not be reached, even after retrying.
    #[error("could not reach witness at {url} after {attempts} attempts: {cause}; check the URL and that the witness is running")]
    WitnessUnreachable {
        /// The witness base URL that failed.
        url: String,
        /// How many attempts were made before giving up.
        attempts: u32,
        /// The underlying transport error.
        cause: String,
    },

    /// The credential is not known locally or to the issuer's registry.
    #[error("credential {id} not found; if it was issued by someone else, import the issuer first with import_contact()")]
    CredentialNotFound {
        /// The credential that could not be found.
        id: CredentialId,
    },

    /// An input string or payload could not be parsed.
    #[error("this input is not a valid {expected}: {cause}")]
    InvalidInput {
        /// What the input was expected to be.
        expected: &'static str,
        /// Why parsing failed.
        cause: String,
    },

    /// Reading or writing local state failed.
    #[error("storage error at {path}: {cause}")]
    Storage {
        /// The file or directory involved.
        path: PathBuf,
        /// The underlying I/O error.
        cause: String,
    },

    /// Importing a contact's key history failed.
    #[error("could not import contact {id}: {cause}")]
    ContactImportFailed {
        /// The identity whose history could not be imported.
        id: String,
        /// What went wrong.
        cause: String,
    },

    /// A multi-party flow (delegation, multisig) is waiting on another party.
    #[error("a step in a multi-party flow is pending: {what}; call pending_requests() on the other party and approve")]
    PendingApproval {
        /// Which approval is outstanding.
        what: String,
    },

    /// A lower-level SDK error with no friendlier mapping.
    #[error(transparent)]
    Advanced(#[from] crate::advanced::Error),
}

impl From<keri_controller::identifier::mechanics::MechanicsError> for Error {
    fn from(e: keri_controller::identifier::mechanics::MechanicsError) -> Self {
        Error::Advanced(e.into())
    }
}

impl Error {
    /// Whether retrying the same operation may succeed (network-flavoured
    /// failures). Drives the facade's internal retry loop.
    pub(crate) fn is_transient(&self) -> bool {
        match self {
            Error::WitnessUnreachable { .. } => true,
            Error::Advanced(inner) => advanced_is_transient(inner),
            _ => false,
        }
    }
}

fn advanced_is_transient(e: &crate::advanced::Error) -> bool {
    use keri_controller::error::ControllerError;
    match e {
        crate::advanced::Error::Mechanics(m) => mechanics_is_transient(m),
        crate::advanced::Error::Controller(ControllerError::SendingError(_)) => true,
        crate::advanced::Error::Controller(ControllerError::Mechanic(m)) => {
            mechanics_is_transient(m)
        }
        _ => false,
    }
}

fn mechanics_is_transient(m: &keri_controller::identifier::mechanics::MechanicsError) -> bool {
    use keri_controller::identifier::mechanics::MechanicsError;
    matches!(
        m,
        MechanicsError::Transport(_) | MechanicsError::SendingError(_)
    )
}

/// Convenience alias — all high-level API functions return this type.
pub type Result<T> = std::result::Result<T, Error>;
