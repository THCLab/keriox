//! # keri-sdk
//!
//! A high-level, stable Rust SDK for the [KERI] (Key Event Receipt
//! Infrastructure) protocol.
//!
//! This crate wraps [`keri-controller`] and exposes a clean public API that
//! hides CESR encoding details, signing internals, and database generics.
//! Consumers only import `keri_sdk::*`.
//!
//! [KERI]: https://keri.one
//!
//! ## Typical workflow
//!
//! ### Create an identifier
//!
//! ```no_run
//! use keri_sdk::{store::KeriStore, types::IdentifierConfig};
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> keri_sdk::Result<()> {
//! let store = KeriStore::open(PathBuf::from("/tmp/my-keri-store"))?;
//! let config = IdentifierConfig::default(); // no witnesses, no watchers
//! let (identifier, signer) = store.create("alice", config).await?;
//! println!("Identifier: {}", identifier.id());
//! # Ok(())
//! # }
//! ```
//!
//! ### Sign and verify a message
//!
//! ```no_run
//! use keri_sdk::{signing, store::KeriStore, types::IdentifierConfig};
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> keri_sdk::Result<()> {
//! let store = KeriStore::open(PathBuf::from("/tmp/my-keri-store"))?;
//! let (identifier, signer) = store.create("bob", IdentifierConfig::default()).await?;
//!
//! let envelope = signing::sign(&identifier, &signer, b"hello world")?;
//! let verified = signing::verify(&identifier, envelope.cesr.as_bytes())?;
//! assert_eq!(verified.payload, b"hello world");
//! # Ok(())
//! # }
//! ```
//!
//! ### Issue and check a credential
//!
//! ```no_run
//! use keri_sdk::{
//!     operations::{incept_registry, issue_str},
//!     tel::check_credential_status_str,
//!     store::KeriStore,
//!     types::IdentifierConfig,
//! };
//! use std::path::PathBuf;
//!
//! # #[tokio::main]
//! # async fn main() -> keri_sdk::Result<()> {
//! let store = KeriStore::open(PathBuf::from("/tmp/my-keri-store"))?;
//! let (mut id, signer) = store.create("issuer", IdentifierConfig::default()).await?;
//!
//! let registry_id = incept_registry(&mut id, signer.clone()).await?;
//!
//! let cred_said = "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM";
//! issue_str(&mut id, signer.clone(), cred_said).await?;
//!
//! // registry_id.to_str() converts IdentifierPrefix to its CESR text form
//! use keri_sdk::CesrPrimitive;
//! let status = check_credential_status_str(&id, &signer, &registry_id.to_str(), cred_said).await?;
//! println!("Status: {:?}", status);
//! # Ok(())
//! # }
//! ```

pub mod advanced;
pub mod controller;
pub mod error;
pub mod identifier;
pub mod keys;
pub mod operations;
pub mod signing;
pub mod store;
pub mod tel;
pub mod types;

#[cfg(feature = "keyprovider")]
pub mod keyprovider_adapter;

// ── High-level SDK types (the primary public API) ────────────────────────────

pub use controller::Controller;
pub use error::{Error, Result};
pub use identifier::Identifier;
pub use identifier::{ActionRequired, WatcherResponseError};
pub use store::KeriStore;
pub use tel::{check_credential_status, get_credential_status};
pub use types::{
    CredentialStatus, DelegationConfig, DelegationRequest, IdentifierConfig, MultisigConfig,
    MultisigRequest, PendingRequest, RotationConfig, SignedEnvelope, VerifiedPayload,
};

#[cfg(feature = "keyprovider")]
pub use keyprovider_adapter::KeriSigner;
#[cfg(feature = "keyprovider")]
pub use keri_keyprovider::KeyProvider;

// ── Commonly-needed prefix / key types ───────────────────────────────────────
// These appear in public API signatures and are needed by most consumers.

pub use keri_controller::{
    BasicPrefix, CesrPrimitive, IdentifierPrefix, LocationScheme, Oobi, SeedPrefix,
    SelfSigningPrefix,
};
pub use keri_core::{actor::prelude::SelfAddressingIdentifier, signer::Signer};

// ── Advanced types (re-exported for backward compatibility) ──────────────────
// Prefer importing from `keri_sdk::advanced::*` for low-level access.
// These re-exports will be removed in a future major version.

pub use keri_controller::config::ControllerConfig;
pub use keri_controller::identifier::query::QueryResponse;
pub use keri_controller::{EndRole, KeyManager};
pub use keri_core::{
    event::sections::seal::EventSeal, event_message::signature::Signature,
    prefix::IndexedSignature, query::query_event::QueryEvent,
};
pub use teliox::query::TelQueryEvent;
pub use teliox::state::{vc_state::TelState, ManagerTelState};

// Full crate re-exports for advanced consumers — prefer `keri_sdk::advanced::*`
pub use cesrox;
pub use keri_controller;
pub use keri_core;
pub use said;
