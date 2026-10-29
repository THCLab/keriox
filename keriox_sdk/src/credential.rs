//! Credentials: ACDC 2.0 documents whose state (issued, revoked) the issuer
//! records in a registry of each credential's own.
//!
//! The registry's state is blinded: only the issuer, and the holder it
//! hands the credential to, can tell it. The holder shows a verifier the
//! credential together with its registry, a *presentation*; the verifier
//! checks it against the issuer's key history. Nothing is looked up on the
//! network: a verifier learns of a revocation when it is presented with the
//! revoked state.

use crate::ids::{CredentialId, IdentityId};

/// What a verifier concludes about a presented credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// Issued and not revoked, as presented — valid.
    Issued,
    /// Revoked by the issuer — no longer valid.
    Revoked,
    /// Not yet decidable: typically the issuer's key history does not yet
    /// hold the events anchoring the presented registry. Refresh the
    /// issuer ([`crate::Keri::import_contact`]) and try again.
    Indeterminate(String),
    /// The presentation does not hold: a broken or forked registry, a state
    /// that is not this credential's, or an issuer the policy refuses.
    Rejected(String),
}

impl CredentialStatus {
    /// `true` only for [`CredentialStatus::Issued`].
    pub fn is_valid(&self) -> bool {
        matches!(self, CredentialStatus::Issued)
    }
}

impl From<teliox::registry::Verdict> for CredentialStatus {
    fn from(verdict: teliox::registry::Verdict) -> Self {
        use teliox::registry::Verdict;
        match verdict {
            Verdict::Valid { state, .. } => match state.state.as_deref() {
                Some("issued") => CredentialStatus::Issued,
                Some("revoked") => CredentialStatus::Revoked,
                Some(other) => CredentialStatus::Rejected(format!("unknown state {other:?}")),
                None => CredentialStatus::Rejected("the registry discloses no state".into()),
            },
            Verdict::Indeterminate(e) => CredentialStatus::Indeterminate(e.to_string()),
            Verdict::Rejected(e) => CredentialStatus::Rejected(e.to_string()),
        }
    }
}

/// A credential issued through [`crate::Identity::issue`].
#[derive(Debug, Clone)]
pub struct Credential {
    /// The credential's id: its registry and its SAID.
    pub id: CredentialId,
    /// The ACDC.
    pub acdc: acdc::Acdc,
    /// Who issued it.
    pub issuer: IdentityId,
    /// The credential with its registry as issued, as one CESR stream: hand
    /// it to the holder, who shows it to verifiers.
    pub presentation: Vec<u8>,
}

/// A credential granted to one of this store's identities, as
/// [`crate::Identity::receive_grant`] read it.
#[derive(Debug, Clone)]
pub struct ReceivedCredential {
    /// Who granted it: its issuer, or a holder presenting it.
    pub from: IdentityId,
    /// The ACDC.
    pub acdc: acdc::Acdc,
    /// Its state, as presented.
    pub status: CredentialStatus,
    /// The message of the grant.
    pub message: Option<String>,
    /// The credential with its registry: keep it to present the credential
    /// in turn.
    pub presentation: Vec<u8>,
}
