//! Protocol-level re-exports for consumers that need direct access to KERI,
//! CESR, SAID, and TEL internals.
//!
//! **Prefer the high-level API** ([`crate::Identifier`], [`crate::KeriStore`],
//! [`crate::operations`]) whenever possible. This module exists so that
//! tools like `dkms-bin` can depend solely on `keri-sdk` without pulling in
//! `keri-core`, `keri-controller`, `cesrox`, `said`, or `teliox` directly.

// ── CESR parsing and encoding ───────────────────────────────────────────────

pub use cesrox::group::Group;
pub use cesrox::payload::Payload;
pub use cesrox::primitives::codes::seed::SeedCode;
pub use cesrox::primitives::codes::self_signing::SelfSigning;
pub use cesrox::value::Value as CesrValue;
pub use cesrox::{parse_all, primitives};

// ── KERI events and messages ────────────────────────────────────────────────

pub use keri_core::actor::event_generator;
pub use keri_core::actor::prelude::Message;
pub use keri_core::event::KeyEvent;
pub use keri_core::event_message::msg::KeriEvent;
pub use keri_core::event_message::signature::{get_signatures, SignerData};
pub use keri_core::event_message::EventTypeTag;
pub use keri_core::keys::PublicKey;
pub use keri_core::mailbox::exchange::{Exchange, ExchangeMessage, ForwardTopic};
pub use keri_core::oobi::Role;
pub use keri_core::processor::validator::{MoreInfoError, VerificationError};
pub use keri_core::state::IdentifierState;

// ── Controller internals ────────────────────────────────────────────────────

pub use keri_controller::controller::Controller as ControllerTrait;
pub use keri_controller::error::ControllerError;
pub use keri_controller::identifier::mechanics::MechanicsError;
pub use keri_controller::identifier::nontransferable::NontransferableIdentifier;
pub use keri_controller::RedbController;

// ── Core errors ─────────────────────────────────────────────────────────────

pub use keri_core::error::Error as CoreError;
pub use keri_core::keys::KeysError;
pub use keri_core::prefix::error::Error as PrefixError;

// ── Event internals ────────────────────────────────────────────────────────

pub use keri_core::event::event_data::EventData;
pub use keri_core::event::sections::threshold::SignatureThreshold;

// ── Actor / query types ────────────────────────────────────────────────────

pub use keri_core::actor::error::ActorError;
pub use keri_core::actor::possible_response::PossibleResponse;
pub use keri_core::actor::{QueryError, SignedQueryError};
pub use keri_core::database::redb::RedbDatabase;
pub use keri_core::oobi_manager::storage::RedbOobiStorage;
pub use keri_controller::communication::SendingError;

// ── TEL ─────────────────────────────────────────────────────────────────────

pub use teliox::database::redb::RedbTelDatabase;

// ── SAID ────────────────────────────────────────────────────────────────────

pub use said::derivation::{HashFunction, HashFunctionCode};
pub use said::error::Error as SaidError;
pub use said::sad::{DerivationCode, SerializationFormats};
pub use said::version::Encode;
