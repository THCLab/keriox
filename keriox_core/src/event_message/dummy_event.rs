use crate::{
    error::Error,
    event::{
        event_data::{DelegatedInceptionEvent, EventData, InceptionEvent},
        SerializationFormats,
    },
    sai::derivation::SelfAddressing,
};

use super::{serialization_info::SerializationInfo, EventTypeTag, Typeable};
use cesrox::primitives::codes::self_addressing::dummy_prefix;
use serde::Serialize;
use serde_hex::{Compact, SerHex};

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
                format,
                Self {
                    serialization_info: SerializationInfo::new(format, 0),
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
        self.serialization_info.kind.encode(&self)
    }
}

#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyEventMessage<T: Serialize, D: Serialize> {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "t")]
    pub event_type: T,
    #[serde(rename = "d")]
    pub digest: String,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> DummyEventMessage<T, D> {
    pub fn dummy_event(
        event: D,
        format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<Self, Error> {
        let cesr_derivation = derivation.clone().into();
        Ok(Self {
            serialization_info: SerializationInfo::new(
                format,
                Self::get_size(&event, format, derivation)?,
            ),
            event_type: event.get_type(),
            data: event,
            digest: dummy_prefix(&cesr_derivation),
        })
    }

    fn get_size(
        event: &D,
        format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<usize, Error> {
        Ok(Self {
            serialization_info: SerializationInfo::new(format, 0),
            event_type: event.get_type(),
            data: event.clone(),
            digest: dummy_prefix(&derivation.into()),
        }
        .serialize()?
        .len())
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info.kind.encode(&self)
    }
}
