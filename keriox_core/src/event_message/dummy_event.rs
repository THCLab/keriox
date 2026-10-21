use crate::{
    error::Error,
    event::event_data::{DelegatedInceptionEvent, EventData, InceptionEvent},
};

use super::{EventTypeTag, Typeable};
use cesrox::primitives::codes::self_addressing::SelfAddressing;
use said::version::{format::SerializationFormats, SerializationInfo};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};
use serde::Serialize;
use serde_hex::{Compact, SerHex};

/// Dummy Inception Event
///
/// Used only to encapsulate the prefix derivation process for inception and
/// delegated inception. The digest and the prefix hold `#` placeholders of
/// the SAID's length, as the SAID is computed over that serialization.
#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyInceptionEvent {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "t")]
    event_type: EventTypeTag,
    #[serde(rename = "d")]
    digest: String,
    #[serde(rename = "i")]
    prefix: String,
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
        let placeholder = "#".repeat(HashFunction::from(derivation.clone()).get_len());
        let tmp_serialization_info = SerializationInfo::new_empty("KERI".to_string(), 1, 0, format);
        let mut tmp_icp = DummyInceptionEvent {
            serialization_info: tmp_serialization_info,
            event_type: data.get_type(),
            digest: placeholder.clone(),
            prefix: placeholder,
            sn: 0,
            data,
        };
        let len = tmp_icp.derivation_data()?.len();
        let serialization_info = SerializationInfo::new("KERI".to_string(), 1, 0, format, len);
        tmp_icp.serialization_info = serialization_info;
        Ok(tmp_icp)
    }

    /// The serialization the SAID of the inception event is computed over.
    pub fn derivation_data(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.serialize(self)?)
    }

    /// The SAID of the inception event, which is also its prefix.
    pub fn said(&self, derivation: &HashFunctionCode) -> Result<SelfAddressingIdentifier, Error> {
        Ok(HashFunction::from(derivation.clone()).derive(&self.derivation_data()?))
    }
}
