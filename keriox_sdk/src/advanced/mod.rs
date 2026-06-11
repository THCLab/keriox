//! Low-level KERI building blocks for power users.
//!
//! Most consumers should use the high-level API in the crate root (`Keri`,
//! `Identity`, …) instead. This module exposes the full mid-level SDK —
//! the alias-based [`store::KeriStore`], the low-level
//! [`identifier::Identifier`], compound async
//! [`operations`], CESR [`signing`] helpers, TEL ([`tel`]) queries, key
//! generation ([`keys`]) and raw protocol types — for use cases the facade
//! does not cover: custom signing flows, direct KEL manipulation, weighted
//! thresholds, out-of-band CESR transport, or building tooling on top of the
//! SDK.

pub mod controller;
pub mod ephemeral;
pub mod error;
pub mod identifier;
pub mod inspect;
pub mod keys;
pub mod multisig;
pub mod oobi;
pub mod oobi_store;
pub mod operations;
pub mod protocol;
pub mod signing;
pub mod store;
pub mod tel;
pub mod types;

#[cfg(feature = "keyprovider")]
pub mod keyprovider_adapter;

// ── Primary mid-level types ──────────────────────────────────────────────────

pub use controller::Controller;
pub use ephemeral::EphemeralIdentifier;
pub use error::{Error, Result};
pub use identifier::{ActionRequired, Identifier, WatcherResponseError};
pub use oobi_store::OobiStore;
pub use store::KeriStore;
pub use tel::{check_credential_status, get_credential_status};
pub use types::{
    CredentialStatus, DelegationConfig, DelegationRequest, GroupRotationConfig, IdentifierConfig,
    MultisigConfig, MultisigRequest, PendingRequest, RotationConfig, SignedEnvelope,
    SignerAlgorithm, StoreRotationConfig, VerificationIssue, VerifiedPayload,
};

#[cfg(feature = "keyprovider")]
pub use keri_keyprovider::KeyProvider;
#[cfg(feature = "keyprovider")]
pub use keyprovider_adapter::KeriSigner;

// ── Commonly-needed prefix / key types ───────────────────────────────────────

pub use keri_controller::identifier::mechanics::MechanicsError;
pub use keri_controller::{
    BasicPrefix, CesrPrimitive, IdentifierPrefix, LocationScheme, Oobi, SeedPrefix,
    SelfSigningPrefix,
};
pub use keri_core::event::sections::threshold::SignatureThreshold;
pub use keri_core::event_message::signature::SignerData;
pub use keri_core::oobi::Role;
pub use keri_core::{actor::prelude::SelfAddressingIdentifier, signer::Signer};
pub use said::derivation::{HashFunction, HashFunctionCode};
pub use said::sad::SAD;
pub use said::version::format::SerializationFormats;
pub use said::version::Encode as SaidEncode;

// ── Controller / core / TEL low-level types ──────────────────────────────────

pub use keri_controller::config::ControllerConfig;
pub use keri_controller::identifier::query::QueryResponse;
pub use keri_controller::{EndRole, KeyManager};
pub use keri_core::{
    event::sections::seal::EventSeal, event_message::signature::Signature,
    prefix::IndexedSignature, query::query_event::QueryEvent,
};
pub use teliox::query::TelQueryEvent;
pub use teliox::state::{vc_state::TelState, ManagerTelState};

/// Re-exports of the underlying crates for consumers who need types this
/// module does not surface individually.
pub mod raw {
    pub use cesrox;
    pub use keri_controller;
    pub use keri_core;
    pub use said;
    pub use teliox;
}
