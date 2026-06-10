//! Credentials: documents whose issuance can be publicly revoked.
//!
//! Issuing a credential records its digest in the issuer's public registry
//! (a TEL — transaction event log). Anyone can later check whether the
//! credential is still valid or has been revoked, without contacting the
//! issuer directly.

use crate::ids::{CredentialId, IdentityId};

/// The public lifecycle state of a credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialStatus {
    /// Issued and not revoked — valid.
    Issued,
    /// Revoked by the issuer — no longer valid.
    Revoked,
    /// Not found in any registry known to this store. Either it was never
    /// issued, or the issuer's registry has not been imported/refreshed yet.
    Unknown,
}

impl CredentialStatus {
    /// `true` only for [`CredentialStatus::Issued`].
    pub fn is_valid(&self) -> bool {
        matches!(self, CredentialStatus::Issued)
    }
}

impl From<crate::advanced::types::CredentialStatus> for CredentialStatus {
    fn from(s: crate::advanced::types::CredentialStatus) -> Self {
        match s {
            crate::advanced::types::CredentialStatus::Issued => CredentialStatus::Issued,
            crate::advanced::types::CredentialStatus::Revoked => CredentialStatus::Revoked,
            crate::advanced::types::CredentialStatus::Unknown => CredentialStatus::Unknown,
        }
    }
}

/// A credential issued through [`crate::Identity::issue`].
#[derive(Debug, Clone)]
pub struct Credential {
    /// The credential's id — give this to anyone who needs to check its
    /// status; it is self-contained (`"<registry>:<digest>"`).
    pub id: CredentialId,
    /// The credential document. If it was JSON with a `d` field, the field
    /// now holds the credential's digest (SAID).
    pub payload: Vec<u8>,
    /// Who issued it.
    pub issuer: IdentityId,
}

impl Credential {
    /// The payload as UTF-8 text, if it is text.
    pub fn payload_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.payload).ok()
    }
}
