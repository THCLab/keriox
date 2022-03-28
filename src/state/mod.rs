use crate::{
    error::Error,
    event::{
        event_data::EventData,
        sections::{threshold::SignatureThreshold, KeyConfig},
    },
    event_message::EventTypeTag,
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct LastEstablishmentData {
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub(crate) sn: u64,
    #[serde(rename = "d")]
    pub(crate) digest: SelfAddressingPrefix,
    #[serde(rename = "br")]
    pub(crate) br: Vec<BasicPrefix>,
    #[serde(rename = "ba")]
    pub(crate) ba: Vec<BasicPrefix>,
}

#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    #[serde(rename = "bt")]
    pub tally: SignatureThreshold,

    #[serde(rename = "b")]
    pub witnesses: Vec<BasicPrefix>,
}

impl WitnessConfig {
    pub fn enough_receipts(
        &self,
        receipts_couplets: &[(BasicPrefix, SelfSigningPrefix)],
    ) -> Result<bool, Error> {
        match self.tally.clone() {
            SignatureThreshold::Simple(t) => {
                let proper_receipts = receipts_couplets
                    .iter()
                    .filter(|(witness, _sig)| self.witnesses.contains(witness))
                    .count();
                Ok(proper_receipts >= t as usize)
            }
            SignatureThreshold::Weighted(t) => {
                let (attached_signatures, _rest): (Vec<Option<AttachedSignaturePrefix>>, _) =
                    receipts_couplets
                        .iter()
                        .map(|(id, signature)| {
                            let index = self.witnesses.iter().position(|wit| wit == id);
                            index.map(|i| AttachedSignaturePrefix {
                                index: i as u16,
                                signature: signature.clone(),
                            })
                        })
                        .partition(Option::is_some);
                let atts = attached_signatures
                    .into_iter()
                    .map(Option::unwrap)
                    .map(|att| att.index as usize)
                    .collect::<Vec<_>>();
                t.enough_signatures(&atts)
            }
        }
    }
}
/// Identifier State
///
/// represents the accumulated state after applying events, based on section 13 of the paper
#[derive(Default, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct IdentifierState {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "d")]
    pub last_event_digest: SelfAddressingPrefix,

    #[serde(rename = "p")]
    pub last_previous: Option<SelfAddressingPrefix>,

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
