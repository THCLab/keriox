//! Pending multi-party requests, surfaced by
//! [`crate::Identity::pending_requests`].
//!
//! Delegation (and group membership, see [`crate::group`]) involves more
//! than one party, so it cannot be a single call: one side starts the flow,
//! the other finds the request in their witness mailbox and approves it.
//! Each variant here wraps everything needed to act on a request with one
//! method call — no event or signature handling required.

use std::sync::Arc;

use crate::error::Result;
use crate::ids::IdentityId;
use crate::keri::KeriInner;

/// A request from another party, waiting for this identity to act.
#[non_exhaustive]
pub enum PendingRequest {
    /// Someone wants to act under your authority (see
    /// [`crate::IdentityBuilder::delegated_by`]). Approve to anchor their
    /// identity in yours.
    Delegation(DelegationApproval),
    /// A group invitation or a group event awaiting your co-signature (see
    /// [`crate::Identity::new_group`]).
    Group(crate::group::GroupRequest),
}

impl PendingRequest {
    /// One-line human-readable description, e.g. for showing in a UI.
    pub fn summary(&self) -> String {
        match self {
            PendingRequest::Delegation(d) => {
                format!("delegation request from {}", d.delegate())
            }
            PendingRequest::Group(g) if g.is_invitation() => {
                format!("invitation to join group {}", g.group_id())
            }
            PendingRequest::Group(g) => {
                format!("group event of {} awaiting your co-signature", g.group_id())
            }
        }
    }
}

impl std::fmt::Debug for PendingRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.summary())
    }
}

/// A delegation request awaiting this identity's approval.
pub struct DelegationApproval {
    pub(crate) keri: Arc<KeriInner>,
    /// The approver's (delegator's) alias.
    pub(crate) alias: String,
    pub(crate) inner: crate::advanced::types::DelegationRequest,
}

impl DelegationApproval {
    /// The identity that will act under your authority once approved.
    pub fn delegate(&self) -> IdentityId {
        // The request carries the anchoring event this identity signs when
        // approving; the delegated identity is named in its seal.
        use keri_core::event::event_data::EventData;
        use keri_core::event::sections::seal::Seal;
        if let EventData::Ixn(ixn) = &self.inner.delegating_event.data.event_data {
            for seal in &ixn.data {
                if let Seal::Event(event_seal) = seal {
                    return IdentityId::from(event_seal.prefix.clone());
                }
            }
        }
        IdentityId::from(self.inner.identifier())
    }

    /// Approve: anchor the delegation in your key history, publish it
    /// through your witnesses, and notify the requester.
    pub async fn approve(self) -> Result<()> {
        let DelegationApproval { keri, alias, inner } = self;
        let signer = keri.store.load_signer(&alias)?;
        let retry = keri.retry.clone();
        crate::retry::with_retry(&retry, || {
            let signer = signer.clone();
            let request = inner.clone();
            let keri = keri.clone();
            let alias = alias.clone();
            async move {
                let mut identifier = keri.store.load(&alias)?;
                Ok(crate::advanced::operations::approve_delegation(
                    &mut identifier,
                    &signer,
                    request,
                )
                .await?)
            }
        })
        .await
    }
}

/// A delegated identity waiting for the delegator's approval.
///
/// Returned by [`crate::IdentityBuilder::build_delegation_request`]. Keep it
/// (or recover it after a restart with
/// [`crate::Keri::delegation_in_progress`]) and call
/// [`DelegationHandle::finalize`] once the delegator has approved.
pub struct DelegationHandle {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) alias: String,
    pub(crate) delegated: keri_controller::IdentifierPrefix,
    pub(crate) delegator: keri_controller::IdentifierPrefix,
}

impl DelegationHandle {
    /// The id the delegated identity will have once finalized.
    pub fn delegated_id(&self) -> IdentityId {
        IdentityId::from(self.delegated.clone())
    }

    /// Who must approve this request.
    pub fn delegator_id(&self) -> IdentityId {
        IdentityId::from(self.delegator.clone())
    }

    /// Complete the delegation after the delegator approved it.
    ///
    /// Collects the delegator's anchoring event from the witnesses and
    /// returns the ready-to-use delegated [`crate::Identity`]. Fails with a
    /// pending-approval error if the delegator has not approved yet — safe
    /// to retry later.
    pub async fn finalize(self) -> Result<crate::Identity> {
        // complete_delegation needs the delegator's key history in this
        // identity's own database; copy it from wherever this store already
        // knows it (an own identity or an imported contact).
        self.ingest_delegator_kel()?;

        let signer = self.keri.store.load_signer(&self.alias)?;
        let retry = self.keri.retry.clone();
        crate::retry::with_retry(&retry, || {
            let signer = signer.clone();
            let delegated = self.delegated.clone();
            let delegator = self.delegator.clone();
            let keri = self.keri.clone();
            let alias = self.alias.clone();
            async move {
                let mut temp_id = keri.store.load(&alias)?;
                Ok(crate::advanced::operations::complete_delegation(
                    &mut temp_id,
                    &signer,
                    &delegated,
                    &delegator,
                )
                .await?)
            }
        })
        .await?;

        // Confirm the delegated identity is now accepted locally.
        let temp_id = self.keri.store.load(&self.alias)?;
        if temp_id.find_state(&self.delegated).is_err() {
            return Err(crate::error::Error::PendingApproval {
                what: format!(
                    "delegation of {} by {}; once approved, call finalize() again",
                    self.delegated, self.delegator
                ),
            });
        }

        // The alias now refers to the delegated identity.
        self.keri.store.save_id(&self.alias, &self.delegated)?;
        let keri = crate::Keri::from_inner(self.keri.clone());
        keri.identity(&self.alias)
    }

    /// Copy the delegator's key history into this alias's database from any
    /// identity or contact in the store that already has it.
    fn ingest_delegator_kel(&self) -> Result<()> {
        self.keri.copy_kel_into(&self.alias, &self.delegator)
    }
}
