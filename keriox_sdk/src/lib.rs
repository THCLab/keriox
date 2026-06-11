//! # keri-sdk
//!
//! A high-level, stable Rust SDK for the [KERI] (Key Event Receipt
//! Infrastructure) protocol.
//!
//! The crate is being reorganized around a simple facade API; the full
//! mid-level SDK lives under [`advanced`].
//!
//! [KERI]: https://keri.one

pub mod advanced;

// ── Facade modules ────────────────────────────────────────────────────────────

mod contact;
mod credential;
mod error;
mod group;
mod identity;
mod ids;
mod keri;
mod message;
mod requests;
mod retry;

pub use credential::{Credential, CredentialStatus};
pub use error::{Error, Result};
pub use group::{Group, GroupBuilder, GroupInvite, GroupRequest};
pub use identity::{Identity, IdentityBuilder, KeyAlgorithm};
pub use ids::{CredentialId, IdentityId};
pub use keri::Keri;
pub use message::{SignedMessage, Verified};
pub use requests::{DelegationApproval, DelegationHandle, PendingRequest};
pub use retry::RetryPolicy;

// ── Temporary transitional re-exports ─────────────────────────────────────────
// Keep existing `keri_sdk::store::…`-style paths compiling while the facade is
// built. Removed once the facade surface is locked.

pub use advanced::controller;
pub use advanced::ephemeral;
pub use advanced::identifier;
pub use advanced::inspect;
pub use advanced::keys;
pub use advanced::multisig;
pub use advanced::oobi;
pub use advanced::oobi_store;
pub use advanced::operations;
pub use advanced::protocol;
pub use advanced::signing;
pub use advanced::store;
pub use advanced::tel;
pub use advanced::types;

#[cfg(feature = "keyprovider")]
pub use advanced::keyprovider_adapter;

pub use advanced::{
    ActionRequired, Controller, EphemeralIdentifier, Identifier, KeriStore, OobiStore,
    WatcherResponseError,
};
pub use advanced::{
    DelegationConfig, DelegationRequest, GroupRotationConfig, IdentifierConfig, MultisigConfig,
    MultisigRequest, RotationConfig, SignedEnvelope, SignerAlgorithm, StoreRotationConfig,
    VerificationIssue, VerifiedPayload,
};
pub use advanced::{check_credential_status, get_credential_status};

#[cfg(feature = "keyprovider")]
pub use advanced::{KeriSigner, KeyProvider};

pub use advanced::{
    BasicPrefix, CesrPrimitive, ControllerConfig, EndRole, EventSeal, HashFunction,
    HashFunctionCode, IdentifierPrefix, IndexedSignature, KeyManager, LocationScheme,
    ManagerTelState, MechanicsError, Oobi, QueryEvent, QueryResponse, Role, SaidEncode,
    SeedPrefix, SelfAddressingIdentifier, SelfSigningPrefix, SerializationFormats, Signature,
    SignatureThreshold, Signer, SignerData, TelQueryEvent, TelState,
};
pub use said::sad::SAD;

// Full crate re-exports — prefer `keri_sdk::advanced::raw::*`
pub use cesrox;
pub use keri_controller;
pub use keri_core;
pub use said;
pub use teliox;
