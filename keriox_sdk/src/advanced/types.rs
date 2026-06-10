//! Typed config structs and result types for keri-sdk operations.
//!
//! These structs replace long positional argument lists throughout the SDK.
//! Import them with `use keri_sdk::*` (they are re-exported from the crate
//! root) or qualify them as `keri_sdk::IdentifierConfig` etc.
//!
//! See [`crate::advanced::operations`] for the functions that accept these structs, and
//! [`crate::advanced::signing`] for `SignedEnvelope` / `VerifiedPayload` usage.

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme};
pub use keri_core::signer::SignerAlgorithm;

// ── Creation / rotation config ────────────────────────────────────────────────

/// Configuration for creating a new KERI identifier.
///
/// Used by [`crate::advanced::operations::create_identifier`] and
/// [`crate::advanced::store::KeriStore::create`].
///
/// Defaults to Ed25519. Use [`with_algorithm`](Self::with_algorithm) (or
/// preset constructors like [`p256`](Self::p256) /
/// [`secp256k1`](Self::secp256k1)) to pick a different curve — the most
/// common reason is to derive an AID whose controlling key lives in
/// platform-native crypto (iOS Secure Enclave, Android Keystore: P-256).
#[derive(Debug, Clone)]
pub struct IdentifierConfig {
    /// Witness OOBIs to include in the inception event.
    pub witnesses: Vec<LocationScheme>,
    /// Signing threshold required for witness receipts.
    pub witness_threshold: u64,
    /// Watcher OOBIs to configure after inception.
    pub watchers: Vec<LocationScheme>,
    /// Algorithm to use when generating the current and next signing keys.
    pub algorithm: SignerAlgorithm,
}

impl Default for IdentifierConfig {
    fn default() -> Self {
        Self {
            witnesses: vec![],
            witness_threshold: 0,
            watchers: vec![],
            algorithm: SignerAlgorithm::Ed25519,
        }
    }
}

impl IdentifierConfig {
    /// Replace the signing algorithm and return self for chaining.
    pub fn with_algorithm(mut self, algorithm: SignerAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// `IdentifierConfig` defaulting to P-256 (NIST secp256r1).
    pub fn p256() -> Self {
        Self::default().with_algorithm(SignerAlgorithm::EcdsaSecp256r1)
    }

    /// `IdentifierConfig` defaulting to secp256k1 (Bitcoin curve).
    pub fn secp256k1() -> Self {
        Self::default().with_algorithm(SignerAlgorithm::EcdsaSecp256k1)
    }
}

/// Configuration for rotating an identifier's keys.
///
/// Used by [`crate::advanced::operations::rotate`].
#[derive(Debug, Clone)]
pub struct RotationConfig {
    /// The new *next* (pre-rotated) public key.
    pub new_next_pk: BasicPrefix,
    /// New pre-rotation (next-key) signing threshold.
    pub new_next_threshold: u64,
    /// Witnesses to add during this rotation.
    pub witness_to_add: Vec<LocationScheme>,
    /// Witnesses to remove during this rotation.
    pub witness_to_remove: Vec<BasicPrefix>,
    /// New witness signing threshold (0 = keep current).
    pub witness_threshold: u64,
}

/// Configuration for a store-managed key rotation with witness changes.
///
/// Used by [`crate::advanced::store::KeriStore::rotate_with`]. For a plain key roll
/// with no witness changes, [`crate::advanced::store::KeriStore::rotate`] needs no
/// configuration at all.
#[derive(Debug, Clone, Default)]
pub struct StoreRotationConfig {
    /// Witnesses to add during this rotation.
    pub witness_to_add: Vec<LocationScheme>,
    /// Witnesses to remove during this rotation.
    pub witness_to_remove: Vec<BasicPrefix>,
    /// New witness signing threshold (0 = keep current).
    pub witness_threshold: u64,
    /// The seed for the new *next* (pre-rotated) key. Generated when `None`,
    /// matching the algorithm of the key becoming current.
    pub new_next_seed: Option<keri_core::prefix::SeedPrefix>,
    /// New pre-rotation (next-key) signing threshold.
    pub new_next_threshold: u64,
}

// ── Delegation config ────────────────────────────────────────────────────────

/// Configuration for creating a delegated identifier (delegatee side).
///
/// Used by [`crate::advanced::operations::request_delegation`] and
/// [`crate::advanced::store::KeriStore::create_delegated`].
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
    /// Algorithm to use when generating the delegatee's signing keys.
    /// Defaults to Ed25519.
    pub algorithm: SignerAlgorithm,
}

impl DelegationConfig {
    pub fn with_algorithm(mut self, algorithm: SignerAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }
}

/// A pending delegation request discovered by the delegator.
///
/// Extracted from [`ActionRequired::DelegationRequest`] via [`DelegationRequest::try_from`].
/// Pass this to [`crate::advanced::operations::approve_delegation`] to approve.
#[derive(Debug, Clone)]
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

    /// Build a request from raw CESR strings delivered out-of-band
    /// (e.g. over a direct peer channel that bypasses the witness
    /// mailbox). The delegating event must be a key event; the
    /// exchange must be an exchange message.
    pub fn from_cesr(event_cesr: &str, exchange_cesr: &str) -> crate::advanced::error::Result<Self> {
        use keri_core::event_message::cesr_adapter::{parse_event_type, EventType};
        let ev = parse_event_type(event_cesr.as_bytes())
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))?;
        let delegating_event = match ev {
            EventType::KeyEvent(ke) => ke,
            _ => {
                return Err(crate::advanced::error::Error::EncodingError(
                    "delegating event is not a key event".into(),
                ))
            }
        };
        let parsed_exn = parse_event_type(exchange_cesr.as_bytes())
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))?;
        let exchange = match parsed_exn {
            EventType::Exn(exn) => exn,
            _ => {
                return Err(crate::advanced::error::Error::EncodingError(
                    "exchange is not an exn message".into(),
                ))
            }
        };
        Ok(DelegationRequest {
            delegating_event,
            exchange,
        })
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
/// Used by [`crate::advanced::operations::create_multisig`] and
/// [`crate::advanced::store::KeriStore::create_multisig_group`].
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

/// Configuration for rotating an established multisig (group) identifier.
///
/// Used by [`crate::advanced::operations::rotate_group`] and
/// [`crate::advanced::store::KeriStore::rotate_multisig_group`].
///
/// The post-rotation member set is given by `new_participants`. Removal
/// and key refresh are supported in a single rotation; **adding** a
/// member whose next-key digest was not previously committed via the
/// prior establishment event is rejected by KERI verifiers because of
/// pre-rotation digest binding.
#[derive(Debug, Default, Clone)]
pub struct GroupRotationConfig {
    /// Full post-rotation member set (caller included if remaining).
    pub new_participants: Vec<IdentifierPrefix>,
    /// Number of signatures required to authorise group events after rotation.
    pub new_signature_threshold: u64,
    /// New pre-rotation threshold. Defaults to `new_signature_threshold` when `None`.
    pub new_next_threshold: Option<u64>,
    /// Witnesses to add during this rotation.
    pub witness_to_add: Vec<LocationScheme>,
    /// Witnesses to remove during this rotation.
    pub witness_to_remove: Vec<BasicPrefix>,
    /// New witness signing threshold. Defaults to the group's current threshold when `None`.
    pub witness_threshold: Option<u64>,
}

/// A pending multisig request discovered in the mailbox.
///
/// Extracted from [`ActionRequired::MultisigRequest`] via [`MultisigRequest::try_from`].
/// Pass this to [`crate::advanced::operations::accept_multisig`] to co-sign the event.
#[derive(Debug, Clone)]
pub struct MultisigRequest {
    pub(crate) event: keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
    pub(crate) exchange: keri_core::mailbox::exchange::ExchangeMessage,
}

impl MultisigRequest {
    /// The group identifier prefix this request is for.
    pub fn group_prefix(&self) -> IdentifierPrefix {
        self.event.data.get_prefix()
    }

    /// Build a request from raw CESR strings delivered out-of-band
    /// (e.g. over a direct peer channel that bypasses the witness
    /// mailbox). The event must be a key event (icp/rot/ixn/dip/drt);
    /// the exchange must be an exchange message.
    pub fn from_cesr(event_cesr: &str, exchange_cesr: &str) -> crate::advanced::error::Result<Self> {
        use keri_core::event_message::cesr_adapter::{parse_event_type, EventType};
        let ev = parse_event_type(event_cesr.as_bytes())
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))?;
        let event = match ev {
            EventType::KeyEvent(ke) => ke,
            _ => {
                return Err(crate::advanced::error::Error::EncodingError(
                    "multisig event is not a key event".into(),
                ))
            }
        };
        let parsed_exn = parse_event_type(exchange_cesr.as_bytes())
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))?;
        let exchange = match parsed_exn {
            EventType::Exn(exn) => exn,
            _ => {
                return Err(crate::advanced::error::Error::EncodingError(
                    "exchange is not an exn message".into(),
                ))
            }
        };
        Ok(MultisigRequest { event, exchange })
    }

    /// Consume and return the underlying `ActionRequired` for low-level storage.
    pub fn into_action_required(self) -> keri_controller::mailbox_updating::ActionRequired {
        keri_controller::mailbox_updating::ActionRequired::MultisigRequest(
            self.event,
            self.exchange,
        )
    }

    /// The SAID of the pending group event.
    ///
    /// # Errors
    /// - [`crate::advanced::Error::EncodingError`] if digest computation fails.
    pub fn event_digest(
        &self,
    ) -> crate::advanced::error::Result<keri_core::actor::prelude::SelfAddressingIdentifier> {
        self.event
            .digest()
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))
    }

    /// `true` when the pending event is a group (or delegated) inception.
    pub fn is_inception(&self) -> bool {
        matches!(
            self.event.event_type,
            keri_core::event_message::EventTypeTag::Icp
                | keri_core::event_message::EventTypeTag::Dip
        )
    }

    /// The pending group event serialised as JSON, suitable for persistence.
    ///
    /// # Errors
    /// - [`crate::advanced::Error::EncodingError`] on serialisation failure.
    pub fn event_json(&self) -> crate::advanced::error::Result<String> {
        serde_json::to_string(&self.event)
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))
    }

    /// Pretty-printed JSON of the pending group event, for display.
    ///
    /// # Errors
    /// - [`crate::advanced::Error::EncodingError`] on serialisation failure.
    pub fn event_json_pretty(&self) -> crate::advanced::error::Result<String> {
        serde_json::to_string_pretty(&self.event)
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))
    }

    /// The exchange message serialised as JSON, suitable for persistence.
    ///
    /// # Errors
    /// - [`crate::advanced::Error::EncodingError`] on serialisation failure.
    pub fn exchange_json(&self) -> crate::advanced::error::Result<String> {
        serde_json::to_string(&self.exchange)
            .map_err(|e| crate::advanced::error::Error::EncodingError(e.to_string()))
    }

    /// Rebuild a request from JSON produced by [`event_json`](Self::event_json)
    /// and [`exchange_json`](Self::exchange_json).
    ///
    /// # Errors
    /// - [`crate::advanced::Error::EncodingError`] if either JSON is invalid.
    pub fn from_json(event_json: &str, exchange_json: &str) -> crate::advanced::error::Result<Self> {
        let event = serde_json::from_str(event_json)
            .map_err(|e| crate::advanced::error::Error::EncodingError(format!("event JSON: {e}")))?;
        let exchange = serde_json::from_str(exchange_json)
            .map_err(|e| crate::advanced::error::Error::EncodingError(format!("exchange JSON: {e}")))?;
        Ok(MultisigRequest { event, exchange })
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
/// Returned by [`crate::advanced::operations::poll_pending_requests`]. Use the
/// convenience methods or pattern-match to determine the request type
/// and pass it to [`crate::advanced::operations::approve_delegation`] or
/// [`crate::advanced::operations::accept_multisig`] accordingly.
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

// ── Verification issues ──────────────────────────────────────────────────────

/// A single problem found while verifying a CESR stream against known KELs.
///
/// Returned by [`crate::advanced::identifier::Identifier::verify_from_cesr_detailed`].
/// Unlike [`crate::advanced::Error::VerificationFailed`], these variants preserve the
/// underlying cause so callers can react (e.g. resolve a missing OOBI and
/// retry, or report a hard signature mismatch).
#[derive(Debug, Clone)]
pub enum VerificationIssue {
    /// A signature does not match the signed data.
    SignatureInvalid,
    /// The KEL event referenced by a signature seal is not known locally.
    MissingEvent {
        seal: keri_core::event::sections::seal::EventSeal,
    },
    /// The signer's identifier is not known locally.
    UnknownSigner { id: IdentifierPrefix },
    /// The event referenced by a signature seal is not an establishment event.
    NotEstablishment {
        seal: keri_core::event::sections::seal::EventSeal,
    },
    /// The signature carries no signer identifier.
    MissingSignerId,
    /// The stream is not parseable CESR.
    StreamFormat(String),
    /// Any other verification failure.
    Other(String),
}

impl std::fmt::Display for VerificationIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationIssue::SignatureInvalid => {
                write!(f, "Signature doesn't match provided data")
            }
            VerificationIssue::MissingEvent { seal } => {
                write!(f, "Corresponding event not found: {}", seal.prefix)
            }
            VerificationIssue::UnknownSigner { id } => {
                write!(f, "Unknown signer identifier: {}", id)
            }
            VerificationIssue::NotEstablishment { seal } => write!(
                f,
                "Event corresponding to provided seal {:?} should be establishment event.",
                seal
            ),
            VerificationIssue::MissingSignerId => {
                write!(f, "Signature doesn't contain signing identifier")
            }
            VerificationIssue::StreamFormat(e) => write!(f, "Wrong stream format: {}", e),
            VerificationIssue::Other(e) => write!(f, "{}", e),
        }
    }
}

// ── Signing / verification result types ──────────────────────────────────────

/// A CESR-encoded signed payload ready for transport.
///
/// Returned by [`crate::advanced::signing::sign`] and [`crate::advanced::signing::sign_json`].
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
/// Returned by [`crate::advanced::signing::verify`] on success.
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
/// Returned by [`crate::advanced::tel::get_credential_status`] and
/// [`crate::advanced::tel::check_credential_status`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialStatus {
    /// The credential has been issued and is currently valid.
    Issued,
    /// The credential has been revoked.
    Revoked,
    /// The TEL has not been queried yet, or the credential is not known locally.
    Unknown,
}
