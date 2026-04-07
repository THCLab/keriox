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
//!     operations::{incept_registry, issue},
//!     tel::check_credential_status,
//!     store::KeriStore,
//!     types::IdentifierConfig,
//! };
//! use keri_core::actor::prelude::SelfAddressingIdentifier;
//! use std::{path::PathBuf, str::FromStr};
//!
//! # #[tokio::main]
//! # async fn main() -> keri_sdk::Result<()> {
//! let store = KeriStore::open(PathBuf::from("/tmp/my-keri-store"))?;
//! let (mut id, signer) = store.create("issuer", IdentifierConfig::default()).await?;
//!
//! let registry_id = incept_registry(&mut id, signer.clone()).await?;
//!
//! let cred_said: SelfAddressingIdentifier =
//!     "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM".parse().unwrap();
//! issue(&mut id, signer.clone(), cred_said.clone()).await?;
//!
//! let status = check_credential_status(&id, &signer, &registry_id, &cred_said).await?;
//! println!("Status: {:?}", status);
//! # Ok(())
//! # }
//! ```

pub mod controller;
pub mod error;
pub mod identifier;
pub mod operations;
pub mod signing;
pub mod store;
pub mod tel;
pub mod types;

#[cfg(feature = "keyprovider")]
pub mod keyprovider_adapter;

pub use controller::Controller;
pub use error::{Error, Result};
pub use identifier::Identifier;
pub use identifier::{ActionRequired, WatcherResponseError};
pub use types::{
    CredentialStatus, DelegationConfig, DelegationRequest, IdentifierConfig, MultisigConfig,
    MultisigRequest, PendingRequest, RotationConfig, SignedEnvelope, VerifiedPayload,
};
pub use store::KeriStore;
pub use tel::{check_credential_status, get_credential_status};

// Prefix / key types — consumers don't need keri-controller directly
pub use keri_controller::{
    BasicPrefix, CesrPrimitive, EndRole, IdentifierPrefix, KeyManager, LocationScheme, Oobi,
    SeedPrefix, SelfSigningPrefix,
};
pub use keri_controller::config::ControllerConfig;
pub use keri_controller::identifier::query::QueryResponse;

// Core types
pub use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    event::sections::seal::EventSeal,
    event_message::signature::Signature,
    prefix::IndexedSignature,
    signer::Signer,
};

// TEL state types
pub use teliox::state::{vc_state::TelState, ManagerTelState};
pub use teliox::query::TelQueryEvent;

// Watcher/mailbox query types (kept for consumers that need low-level access)
pub use keri_core::query::query_event::QueryEvent;
// Re-export underlying crates for advanced consumers that need low-level access
pub use keri_core;
pub use keri_controller;
pub use cesrox;
pub use said;
