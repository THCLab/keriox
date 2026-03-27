use std::collections::HashSet;

use crate::{
    database::rkyv_adapter::said_wrapper::SaidValue,
    error::Error,
    event::{
        event_data::EventData,
        sections::{threshold::SignatureThreshold, KeyConfig},
    },
    event_message::EventTypeTag,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
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
                // save indexed signer's identifiers
                indexed_receipts.into_iter().for_each(|w| {
                    unique.insert(
                        self.witnesses
                            .get(w.index.current() as usize)
                            .unwrap()
                            .clone(),
                    );
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
                let indexes = receipts_couplets
                    .into_iter()
                    .filter_map(|(id, _signature)| self.witnesses.iter().position(|wit| wit == &id))
                    .chain(
                        indexed_receipts
                            .into_iter()
                            .map(|att| att.index.current() as usize),
                    )
                    .collect::<Vec<_>>();
                match t.enough_signatures(&indexes) {
                    Ok(_) => Ok(true),
                    Err(e) => Err(Error::KeyConfigError(e)),
                }
            }
        }
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
