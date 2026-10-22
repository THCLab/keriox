use std::collections::HashSet;

mod status;
pub use status::{Abandonment, IdentifierStatus};

use crate::{
    database::rkyv_adapter::said_wrapper::SaidValue,
    error::Error,
    event::{
        event_data::EventData,
        sections::{
            key_config::{has_repeats, SignatureError},
            threshold::SignatureThreshold,
            KeyConfig,
        },
    },
    event_message::EventTypeTag,
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    Eq,
    Default,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct LastEstablishmentData {
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub(crate) sn: u64,
    #[serde(rename = "d")]
    pub(crate) digest: SaidValue,
    #[serde(rename = "br")]
    pub(crate) br: Vec<BasicPrefix>,
    #[serde(rename = "ba")]
    pub(crate) ba: Vec<BasicPrefix>,
}

#[derive(
    Default,
    PartialEq,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct WitnessConfig {
    #[serde(rename = "bt")]
    pub tally: SignatureThreshold,

    #[serde(rename = "b")]
    pub witnesses: Vec<BasicPrefix>,
}

impl WitnessConfig {
    /// Checks the witness list as the KERI specification requires: witness
    /// AIDs are non-transferable public keys, each listed once, and the
    /// threshold is an integer the list can meet (0 for an empty list).
    pub fn check(&self) -> Result<(), String> {
        if let Some(witness) = self.witnesses.iter().find(|w| w.is_transferable()) {
            return Err(format!(
                "witness {} has a transferable code",
                witness.to_str()
            ));
        }
        if has_repeats(&self.witnesses) {
            return Err("the witness list must not repeat a witness".to_string());
        }
        match &self.tally {
            SignatureThreshold::Simple(t) if *t as usize > self.witnesses.len() => Err(format!(
                "the witness threshold {t} exceeds the {} witnesses",
                self.witnesses.len()
            )),
            SignatureThreshold::Simple(_) => Ok(()),
            SignatureThreshold::Weighted(_) => {
                Err("the witness threshold must be an integer".to_string())
            }
        }
    }

    pub fn enough_receipts<I, R>(
        &self,
        receipts_couplets: I,
        indexed_receipts: R,
    ) -> Result<bool, Error>
    where
        I: IntoIterator<Item = (BasicPrefix, SelfSigningPrefix)>,
        R: IntoIterator<Item = IndexedSignature>,
    {
        match self.tally.clone() {
            SignatureThreshold::Simple(t) => {
                let mut unique = HashSet::new();
                // save indexed signer's identifiers; an index outside the
                // witness list names no witness and doesn't count
                indexed_receipts
                    .into_iter()
                    .filter_map(|w| self.witnesses.get(w.index.current() as usize))
                    .for_each(|witness| {
                        unique.insert(witness.clone());
                    });
                receipts_couplets
                    .into_iter()
                    .filter(|(witness, _sig)| self.witnesses.contains(witness))
                    .for_each(|(witness_id, _witness_sig)| {
                        unique.insert(witness_id);
                    });
                Ok(unique.len() >= t as usize)
            }
            SignatureThreshold::Weighted(t) => {
                // a witness counts once however many of its receipts arrive,
                // and an index outside the witness list names no witness
                let indexes = receipts_couplets
                    .into_iter()
                    .filter_map(|(id, _signature)| self.witnesses.iter().position(|wit| wit == &id))
                    .chain(
                        indexed_receipts
                            .into_iter()
                            .map(|att| att.index.current() as usize)
                            .filter(|index| *index < self.witnesses.len()),
                    )
                    .collect::<HashSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                match t.enough_signatures(&indexes) {
                    Ok(_) => Ok(true),
                    Err(SignatureError::NotEnoughSigsError) => Ok(false),
                    Err(e) => Err(Error::KeyConfigError(e)),
                }
            }
        }
    }
}
/// Rejects keys that must not enter key state, such as small-order Ed25519
/// keys for which anyone can produce valid signatures.
pub(crate) fn check_keys<'a>(keys: impl IntoIterator<Item = &'a BasicPrefix>) -> Result<(), Error> {
    match keys.into_iter().find(|key| !key.is_valid()) {
        Some(key) => Err(Error::InvalidPublicKey(key.clone())),
        None => Ok(()),
    }
}

/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(
    Default,
    PartialEq,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct IdentifierState {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "d")]
    pub last_event_digest: SaidValue,

    #[serde(rename = "p")]
    pub last_previous: Option<SaidValue>,

    #[serde(rename = "et")]
    pub last_event_type: Option<EventTypeTag>,

    #[serde(flatten)]
    pub current: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,

    #[serde(rename = "di", with = "empty_string_as_none")]
    pub delegator: Option<IdentifierPrefix>,

    #[serde(rename = "ee")]
    pub last_est: LastEstablishmentData,
}

mod empty_string_as_none {
    use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'d, D, T>(de: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'d>,
        T: Deserialize<'d>,
    {
        let opt = Option::<String>::deserialize(de)?;
        let opt = opt.as_deref();
        match opt {
            None | Some("") => Ok(None),
            Some(s) => T::deserialize(s.into_deserializer()).map(Some),
        }
    }

    pub fn serialize<S, T>(t: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        s.serialize_str(&match &t {
            Some(v) => v.to_string(),
            None => "".into(),
        })
    }
}

impl EventTypeTag {
    pub fn is_establishment_event(&self) -> bool {
        matches!(
            self,
            EventTypeTag::Icp | EventTypeTag::Rot | EventTypeTag::Dip | EventTypeTag::Drt
        )
    }
}

impl From<&EventData> for EventTypeTag {
    fn from(ed: &EventData) -> Self {
        match ed {
            EventData::Icp(_) => EventTypeTag::Icp,
            EventData::Rot(_) => EventTypeTag::Rot,
            EventData::Ixn(_) => EventTypeTag::Ixn,
            EventData::Dip(_) => EventTypeTag::Dip,
            EventData::Drt(_) => EventTypeTag::Drt,
        }
    }
}

impl IdentifierState {
    /// Apply
    ///
    /// validates and applies the semantic rules of the event to the event state
    pub fn apply<T: EventSemantics>(self, event: &T) -> Result<Self, Error> {
        event.apply_to(self)
    }

    /// Whether the identifier can still rotate: its last establishment event
    /// committed to next keys. When it did not, the key event log is final
    /// and no more key events are allowed in it.
    pub fn is_transferable(&self) -> bool {
        self.prefix == IdentifierPrefix::default() || !self.current.next_keys_data.is_empty()
    }

    /// Whether the identifier is abandoned: a rotation committed to no next
    /// keys. An inception that does so makes the identifier non-transferable
    /// instead; its log is just as final, but its keys keep speaking for it.
    pub fn is_abandoned(&self) -> bool {
        // Nothing follows the event that ended the log, so an end after sn 0
        // was a rotation.
        !self.is_transferable() && self.sn > 0
    }

    /// Sn and digest of the rotation that abandoned the identifier. Nothing
    /// can follow it, so it is always the last event in the log.
    pub fn abandonment(&self) -> Option<(u64, said::SelfAddressingIdentifier)> {
        self.is_abandoned()
            .then(|| (self.sn, self.last_event_digest.said.clone()))
    }

    /// The error for an event that would follow the end of this log.
    pub fn final_log_error(&self) -> Error {
        if self.is_abandoned() {
            Error::AbandonedIdentifier(self.prefix.clone())
        } else {
            Error::NonTransferableIdentifier(self.prefix.clone())
        }
    }
}

/// EventSemantics
///
/// Describes an interface for applying the semantic rule of an event to the state of an Identifier
pub trait EventSemantics {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        // default impl is the identity transition
        Ok(state)
    }
}
