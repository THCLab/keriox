pub mod config;
pub mod error;
// pub mod identifier_controller;
pub mod communication;
pub mod controller;
pub mod identifier;
pub mod known_events;
pub mod oobi;

mod action_required;
pub use action_required::ActionRequired;

pub use keri_core::oobi::{EndRole, LocationScheme, Oobi};
pub use keri_core::prefix::{
    BasicPrefix, CesrPrimitive, IdentifierPrefix, SeedPrefix, SelfSigningPrefix,
};
pub use keri_core::signer::{CryptoBox, KeyManager};
pub use keri_core::state::{Abandonment, IdentifierState, IdentifierStatus};
/// ACDC 2.0 registries: the issuance and revocation state of credentials.
pub use teliox::registry;

#[cfg(feature = "storage-redb")]
pub use controller::{RedbController, RedbIdentifier};
#[cfg(feature = "storage-redb")]
pub use known_events::RedbKnownEvents;

#[cfg(feature = "storage-postgres")]
pub use controller::{PostgresController, PostgresIdentifier};
#[cfg(feature = "storage-postgres")]
pub use known_events::PostgresKnownEvents;
