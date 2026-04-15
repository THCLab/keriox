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

// ── Delegation config ────────────────────────────────────────────────────────

/// Configuration for creating a delegated identifier (delegatee side).
///
/// Used by [`crate::operations::request_delegation`] and
/// [`crate::store::KeriStore::create_delegated`].
#[derive(Debug, Clone)]
pub struct DelegationConfig {
    /// The delegator's identifier prefix.
    pub delegator: IdentifierPrefix,
    /// Witness OOBIs for the delegated identifier.
    pub witnesses: Vec<LocationScheme>,
    /// Witness signing threshold.
    pub witness_threshold: u64,
    /// Watcher OOBIs to configure after delegation is accepted.
    pub watchers: Vec<LocationScheme>,
}

/// A pending delegation request discovered by the delegator.
///
/// Extracted from [`ActionRequired::DelegationRequest`] via [`DelegationRequest::try_from`].
/// Pass this to [`crate::operations::approve_delegation`] to approve.
#[derive(Debug)]
pub struct DelegationRequest {
    pub(crate) delegating_event:
        keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
    pub(crate) exchange: keri_core::mailbox::exchange::ExchangeMessage,
}

impl DelegationRequest {
    /// The identifier prefix of the delegatee requesting delegation.
    pub fn identifier(&self) -> IdentifierPrefix {
        self.delegating_event.data.get_prefix()
    }

    /// Consume and return the underlying `ActionRequired` for low-level storage.
    pub fn into_action_required(self) -> keri_controller::mailbox_updating::ActionRequired {
        keri_controller::mailbox_updating::ActionRequired::DelegationRequest(
            self.delegating_event,
            self.exchange,
        )
    }
}

impl TryFrom<keri_controller::mailbox_updating::ActionRequired> for DelegationRequest {
    type Error = keri_controller::mailbox_updating::ActionRequired;

    fn try_from(
        action: keri_controller::mailbox_updating::ActionRequired,
    ) -> std::result::Result<Self, Self::Error> {
        match action {
            keri_controller::mailbox_updating::ActionRequired::DelegationRequest(ev, exn) => {
                Ok(DelegationRequest {
                    delegating_event: ev,
                    exchange: exn,
                })
            }
            other => Err(other),
        }
    }
}

// ── Multisig config ──────────────────────────────────────────────────────────

/// Configuration for creating a multisig identifier.
///
/// Used by [`crate::operations::create_multisig`] and
/// [`crate::store::KeriStore::create_multisig_group`].
#[derive(Debug, Clone)]
pub struct MultisigConfig {
    /// Other members' identifier prefixes (not including the caller).
    pub members: Vec<IdentifierPrefix>,
    /// Number of signatures required to authorise a group event.
    pub threshold: u64,
    /// Witness OOBIs for the multisig identifier.
    pub witnesses: Vec<LocationScheme>,
    /// Witness signing threshold.
    pub witness_threshold: u64,
    /// Optional delegator (for a delegated multisig identifier).
    pub delegator: Option<IdentifierPrefix>,
}

/// A pending multisig request discovered in the mailbox.
///
/// Extracted from [`ActionRequired::MultisigRequest`] via [`MultisigRequest::try_from`].
/// Pass this to [`crate::operations::accept_multisig`] to co-sign the event.
#[derive(Debug)]
pub struct MultisigRequest {
    pub(crate) event: keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
    pub(crate) exchange: keri_core::mailbox::exchange::ExchangeMessage,
}

impl MultisigRequest {
    /// The group identifier prefix this request is for.
    pub fn group_prefix(&self) -> IdentifierPrefix {
        self.event.data.get_prefix()
    }

    /// Consume and return the underlying `ActionRequired` for low-level storage.
    pub fn into_action_required(self) -> keri_controller::mailbox_updating::ActionRequired {
        keri_controller::mailbox_updating::ActionRequired::MultisigRequest(
            self.event,
            self.exchange,
        )
    }
}

impl TryFrom<keri_controller::mailbox_updating::ActionRequired> for MultisigRequest {
    type Error = keri_controller::mailbox_updating::ActionRequired;

    fn try_from(
        action: keri_controller::mailbox_updating::ActionRequired,
    ) -> std::result::Result<Self, Self::Error> {
        match action {
            keri_controller::mailbox_updating::ActionRequired::MultisigRequest(ev, exn) => {
                Ok(MultisigRequest {
                    event: ev,
                    exchange: exn,
                })
            }
            other => Err(other),
        }
    }
}

// ── Unified pending request ──────────────────────────────────────────────────

/// A pending request discovered in the mailbox.
///
/// Returned by [`crate::operations::poll_pending_requests`]. Use the
/// convenience methods or pattern-match to determine the request type
/// and pass it to [`crate::operations::approve_delegation`] or
/// [`crate::operations::accept_multisig`] accordingly.
#[derive(Debug)]
pub enum PendingRequest {
    /// A delegation request from a delegatee awaiting approval.
    Delegation(DelegationRequest),
    /// A multisig event from another participant awaiting co-signature.
    Multisig(MultisigRequest),
}

impl PendingRequest {
    /// Returns `true` if this is a delegation request.
    pub fn is_delegation(&self) -> bool {
        matches!(self, Self::Delegation(_))
    }

    /// Returns `true` if this is a multisig request.
    pub fn is_multisig(&self) -> bool {
        matches!(self, Self::Multisig(_))
    }

    /// Consume and return the inner delegation request, if any.
    pub fn into_delegation(self) -> Option<DelegationRequest> {
        match self {
            Self::Delegation(r) => Some(r),
            _ => None,
        }
    }

    /// Consume and return the inner multisig request, if any.
    pub fn into_multisig(self) -> Option<MultisigRequest> {
        match self {
            Self::Multisig(r) => Some(r),
            _ => None,
        }
    }

    /// Consume and return the underlying `ActionRequired` for low-level storage.
    pub fn into_action_required(self) -> keri_controller::mailbox_updating::ActionRequired {
        match self {
            Self::Delegation(r) => r.into_action_required(),
            Self::Multisig(r) => r.into_action_required(),
        }
    }
}

impl TryFrom<keri_controller::mailbox_updating::ActionRequired> for PendingRequest {
    type Error = keri_controller::mailbox_updating::ActionRequired;

    fn try_from(
        action: keri_controller::mailbox_updating::ActionRequired,
    ) -> std::result::Result<Self, Self::Error> {
        match action {
            keri_controller::mailbox_updating::ActionRequired::DelegationRequest(ev, exn) => {
                Ok(PendingRequest::Delegation(DelegationRequest {
                    delegating_event: ev,
                    exchange: exn,
                }))
            }
            keri_controller::mailbox_updating::ActionRequired::MultisigRequest(ev, exn) => {
                Ok(PendingRequest::Multisig(MultisigRequest {
                    event: ev,
                    exchange: exn,
                }))
            }
        }
    }
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
