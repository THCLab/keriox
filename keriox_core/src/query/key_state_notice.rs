use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use said::version::{format::SerializationFormats, SerializationInfo};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

use crate::state::IdentifierState;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KeyStateNotice {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(flatten)]
    pub state: IdentifierState,

    #[serde(rename = "f", with = "SerHex::<Compact>")]
    first_seen_sn: u64,

    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "c")]
    config: Vec<String>,
}

impl Serialize for KeyStateNotice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 17)?;
        em.serialize_field("v", &self.serialization_info)?;
        em.serialize_field("i", &self.state.prefix)?;
        em.serialize_field("s", &self.state.sn.to_string())?;
        em.serialize_field("p", &self.state.last_previous.clone())?;
        em.serialize_field("d", &self.state.last_event_digest)?;
        em.serialize_field("f", &self.first_seen_sn.to_string())?;
        em.serialize_field(
            "dt",
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false),
        )?;
        em.serialize_field("et", &self.state.last_event_type)?;
        em.serialize_field("kt", &self.state.current.threshold)?;
        em.serialize_field("k", &self.state.current.public_keys)?;
        em.serialize_field("nt", &self.state.current.next_keys_data.threshold)?;
        em.serialize_field("n", &self.state.current.next_keys_data.next_keys_hashes())?;
        em.serialize_field("bt", &self.state.witness_config.tally)?;
        em.serialize_field("b", &self.state.witness_config.witnesses)?;
        em.serialize_field("c", &self.config)?;
        em.serialize_field("ee", &self.state.last_est)?;
        em.serialize_field("di", &self.state.delegator.clone().unwrap_or_default())?;
        em.end()
    }
}

impl KeyStateNotice {
    pub fn new_ksn(state: IdentifierState, serialization: SerializationFormats) -> Self {
        let dt: DateTime<FixedOffset> = DateTime::from(Utc::now());

        KeyStateNotice {
            serialization_info: SerializationInfo::new("KERI".to_string(), 1, 0, serialization, 0),
            timestamp: dt,
            state,
            first_seen_sn: 0,
            config: vec![],
        }
    }
}
