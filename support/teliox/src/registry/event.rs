//! The messages of an ACDC 2.0 state registry (TEL): registry inception
//! `rip`, blindable update `bup` and update `upd`, as acdc-rust reads and
//! writes them. They are ACDC protocol messages, not KERI ones, and carry no
//! signatures: each is committed to by a seal in the Issuer's KEL.

use acdc::{
    message::Message,
    registry::{BlindableUpdate, RegistryInception, Update},
    HashFunctionCode, Kind,
};
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use keri_core::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;

use super::RegistryError;

/// The message type, `t`, of a registry event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryIlk {
    Rip,
    Bup,
    Upd,
}

/// Any registry event.
#[derive(Debug, Clone, PartialEq)]
pub enum RegistryMessage {
    Inception(RegistryInception),
    Blindable(BlindableUpdate),
    Update(Update),
}

fn format(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Format(e.to_string())
}

fn said(text: &str) -> Result<SelfAddressingIdentifier, RegistryError> {
    text.parse()
        .map_err(|_| RegistryError::Format(format!("{text} is not a SAID")))
}

/// A date-time as registry events carry it: microseconds and a numeric UTC
/// offset.
pub(crate) fn datetime(time: &DateTime<FixedOffset>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Micros, false)
}

/// The time now, as registry events carry it.
pub(crate) fn now() -> String {
    datetime(&Utc::now().into())
}

const CODE: HashFunctionCode = HashFunctionCode::Blake3_256;

impl RegistryMessage {
    /// Reads a registry event body. It must be exactly one ACDC 2.x registry
    /// event whose SAID verifies.
    pub fn parse(raw: &[u8]) -> Result<Self, RegistryError> {
        let (message, size) = Message::parse(raw).map_err(format)?;
        if size != raw.len() {
            return Err(RegistryError::Format(format!(
                "{} bytes after the registry event",
                raw.len() - size
            )));
        }
        let message = match message {
            Message::RegistryInception(rip) => RegistryMessage::Inception(rip),
            Message::BlindableUpdate(bup) => RegistryMessage::Blindable(bup),
            Message::Update(upd) => RegistryMessage::Update(upd),
            _ => return Err(RegistryError::Format("not a registry event".into())),
        };
        u64::try_from(message.sn_u128())
            .map_err(|_| RegistryError::Format("sequence number too large".into()))?;
        Ok(message)
    }

    /// A registry inception of `issuer`, made unguessable by `nonce`, a
    /// 128-bit salt.
    pub fn incept(
        issuer: &IdentifierPrefix,
        nonce: &str,
        timestamp: &str,
    ) -> Result<Self, RegistryError> {
        RegistryInception::new(issuer.to_string(), nonce, timestamp, Kind::Json, CODE)
            .map(RegistryMessage::Inception)
            .map_err(format)
    }

    /// The `bup` after `prior`, publishing `blid`.
    pub fn blindable_update(
        prior: &RegistryMessage,
        blid: &SelfAddressingIdentifier,
        timestamp: &str,
    ) -> Result<Self, RegistryError> {
        BlindableUpdate::new(
            prior.registry()?.to_string(),
            prior.sn_u128() + 1,
            prior.said()?.to_string(),
            timestamp,
            blid.to_string(),
            Kind::Json,
            CODE,
        )
        .map(RegistryMessage::Blindable)
        .map_err(format)
    }

    /// The `upd` after `prior`, giving `acdc` the `state` openly.
    pub fn update(
        prior: &RegistryMessage,
        acdc: &SelfAddressingIdentifier,
        state: &str,
        timestamp: &str,
    ) -> Result<Self, RegistryError> {
        Update::new(
            prior.registry()?.to_string(),
            prior.sn_u128() + 1,
            prior.said()?.to_string(),
            timestamp,
            acdc.to_string(),
            state,
            Kind::Json,
            CODE,
        )
        .map(RegistryMessage::Update)
        .map_err(format)
    }

    /// The serialized event.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            RegistryMessage::Inception(event) => event.raw(),
            RegistryMessage::Blindable(event) => event.raw(),
            RegistryMessage::Update(event) => event.raw(),
        }
        .to_vec()
    }

    pub fn ilk(&self) -> RegistryIlk {
        match self {
            RegistryMessage::Inception(_) => RegistryIlk::Rip,
            RegistryMessage::Blindable(_) => RegistryIlk::Bup,
            RegistryMessage::Update(_) => RegistryIlk::Upd,
        }
    }

    /// The event's SAID.
    pub fn said(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        said(match self {
            RegistryMessage::Inception(event) => event.said(),
            RegistryMessage::Blindable(event) => event.said(),
            RegistryMessage::Update(event) => event.said(),
        })
    }

    /// The SAID of the registry the event belongs to: its own for a `rip`.
    pub fn registry(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        match self {
            RegistryMessage::Inception(_) => self.said(),
            RegistryMessage::Blindable(event) => said(event.registry()),
            RegistryMessage::Update(event) => said(event.registry()),
        }
    }

    /// The Issuer, named by the inception.
    pub fn issuer(&self) -> Option<Result<IdentifierPrefix, RegistryError>> {
        match self {
            RegistryMessage::Inception(event) => Some(
                event
                    .issuer()
                    .parse()
                    .map_err(|_| RegistryError::Format("issuer is not an AID".into())),
            ),
            _ => None,
        }
    }

    fn sn_u128(&self) -> u128 {
        match self {
            RegistryMessage::Inception(event) => event.sn(),
            RegistryMessage::Blindable(event) => event.sn(),
            RegistryMessage::Update(event) => event.sn(),
        }
    }

    /// The event's sequence number in its registry.
    pub fn sn(&self) -> u64 {
        // Checked to fit when read or built.
        self.sn_u128() as u64
    }

    /// The SAID of the prior event; none for a `rip`.
    pub fn prior(&self) -> Option<Result<SelfAddressingIdentifier, RegistryError>> {
        match self {
            RegistryMessage::Inception(_) => None,
            RegistryMessage::Blindable(event) => Some(said(event.prior())),
            RegistryMessage::Update(event) => Some(said(event.prior())),
        }
    }

    pub fn timestamp(&self) -> Result<DateTime<FixedOffset>, RegistryError> {
        let text = match self {
            RegistryMessage::Inception(event) => event.datetime(),
            RegistryMessage::Blindable(event) => event.datetime(),
            RegistryMessage::Update(event) => event.datetime(),
        };
        DateTime::parse_from_rfc3339(text).map_err(format)
    }

    /// The BLID a `bup` publishes.
    pub fn blid(&self) -> Option<Result<SelfAddressingIdentifier, RegistryError>> {
        match self {
            RegistryMessage::Blindable(event) => Some(said(event.blid())),
            _ => None,
        }
    }

    /// The ACDC and state an `upd` gives openly.
    pub fn disclosed(&self) -> Option<Result<(SelfAddressingIdentifier, String), RegistryError>> {
        match self {
            RegistryMessage::Update(event) => {
                Some(said(event.acdc()).map(|acdc| (acdc, event.state().to_string())))
            }
            _ => None,
        }
    }
}
