use crate::{
    error::Error,
    event::event_data::{DelegatedInceptionEvent, EventData, InceptionEvent},
    sai::derivation::SelfAddressing,
};

use super::{EventTypeTag, Typeable};
use cesrox::primitives::codes::self_addressing::dummy_prefix;
use serde::Serialize;
use serde_hex::{Compact, SerHex};
use version::{
    serialization_info::{SerializationFormats, SerializationInfo},
    Versional,
};

/// Dummy Inception Event
///
/// Used only to encapsulate the prefix derivation process for inception and delegated inception
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
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        DummyInceptionEvent::derive_data(EventData::Icp(icp), derivation, format)
    }

    pub fn dummy_delegated_inception_data(
        dip: DelegatedInceptionEvent,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        DummyInceptionEvent::derive_data(EventData::Dip(dip), derivation, format)
    }

    fn derive_data(
        data: EventData,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Self, Error> {
        let derivation = derivation.into();
        Ok(Self {
            serialization_info: SerializationInfo::new(
                ['K', 'E', 'R', 'I'],
                format,
                Self {
                    serialization_info: SerializationInfo::new(['K', 'E', 'R', 'I'], format, 0),
                    event_type: data.get_type(),
                    prefix: dummy_prefix(&derivation),
                    digest: dummy_prefix(&derivation),
                    sn: 0,
                    data: data.clone(),
                }
                .serialize()?
                .len(),
            ),
            event_type: data.get_type(),
            digest: dummy_prefix(&derivation),
            prefix: dummy_prefix(&derivation),
            sn: 0,
            data,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.kind.encode(&self).unwrap())
    }
}

/// Dummy Event
///
/// Contains logic for replacing digest field with placeholder during event
/// digest computation process.
#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyEvent<T: Serialize, D: Serialize + Typeable<TypeTag = T>> {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "t")]
    pub event_type: T,
    #[serde(rename = "d")]
    pub digest: String,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T>> Versional for DummyEvent<T, D> {
    fn get_version_str(&self) -> SerializationInfo {
        self.serialization_info
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T>> DummyEvent<T, D> {
    pub fn dummy_event(
        event: D,
        format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<Self, Error> {
        let mut version = SerializationInfo::new_empty(['K', 'E', 'R', 'I'], format);
        let cesr_derivation = derivation.clone().into();
        let dummy_prefix = dummy_prefix(&cesr_derivation);
        let mut dummy_event = DummyEvent {
            serialization_info: version,
            event_type: event.get_type(),
            digest: dummy_prefix,
            data: event,
        };
        let event_len = Versional::serialize(&dummy_event)?.len();
        version.size = event_len;
        dummy_event.serialization_info = version;
        Ok(dummy_event)
    }
}
