use crate::{
    error::Error,
    event::event_data::{DelegatedInceptionEvent, EventData, InceptionEvent},
};

use super::{EventTypeTag, Typeable};
use cesrox::primitives::codes::self_addressing::SelfAddressing;
use sad_macros::SAD;
use said::{derivation::HashFunctionCode, sad::SAD, SelfAddressingIdentifier};
use serde::Serialize;
use serde_hex::{Compact, SerHex};
use version::serialization_info::{SerializationFormats, SerializationInfo};

/// Dummy Inception Event
///
/// Used only to encapsulate the prefix derivation process for inception and delegated inception
#[derive(Serialize, Debug, Clone, SAD)]
pub(crate) struct DummyInceptionEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "t")]
    event_type: EventTypeTag,
    #[serde(rename = "d")]
    #[said]
    digest: Option<SelfAddressingIdentifier>,
    #[serde(rename = "i")]
    #[said]
    pub prefix: Option<SelfAddressingIdentifier>,
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    sn: u8,
    #[serde(flatten)]
    data: EventData,
}

impl DummyInceptionEvent {
    pub fn dummy_inception_data(
        icp: InceptionEvent,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        DummyInceptionEvent::derive_data(EventData::Icp(icp), derivation, format)
    }

    pub fn dummy_delegated_inception_data(
        dip: DelegatedInceptionEvent,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        DummyInceptionEvent::derive_data(EventData::Dip(dip), derivation, format)
    }

    fn derive_data(
        data: EventData,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        let tmp_serialization_info = SerializationInfo::new_empty("KERI".to_string(), format);
        let mut tmp_icp = DummyInceptionEvent {
            serialization_info: tmp_serialization_info,
            event_type: data.get_type(),
            digest: None,
            prefix: None,
            sn: 0,
            data,
        };
        let len = tmp_icp.derivation_data(derivation, &format).len();
        let serialization_info = SerializationInfo::new("KERI".to_string(), format, len);
        tmp_icp.serialization_info = serialization_info;
        Ok(tmp_icp)
    }
}
