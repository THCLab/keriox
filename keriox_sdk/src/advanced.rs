//! Low-level types for power users who need direct access to CESR primitives,
//! keri-controller internals, or keri-core types.
//!
//! Most consumers should use the high-level API in the crate root instead.
//! These re-exports are provided for advanced use cases such as custom signing
//! flows, direct KEL manipulation, or building CESR tooling on top of the SDK.

// Full crate re-exports
pub use cesrox;
pub use keri_controller;
pub use keri_core;
pub use said;

// Controller-level types
pub use keri_controller::config::ControllerConfig;
pub use keri_controller::identifier::query::QueryResponse;
pub use keri_controller::{EndRole, KeyManager};

// Core low-level types
pub use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::Signature,
    prefix::IndexedSignature,
    query::query_event::QueryEvent,
};

// TEL types
pub use teliox::query::TelQueryEvent;
pub use teliox::state::{vc_state::TelState, ManagerTelState};
