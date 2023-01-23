use serde::Serialize;
use version::{serialization_info::{SerializationInfo, SerializationFormats}, message::Message};

use crate::{sai::{SelfAddressingPrefix, derivation::SelfAddressing}, error::Error};

use super::{dummy_event::DummyEvent, Typeable};

#[derive(Serialize)]
pub struct KeriEvent<D> {
    #[serde(rename = "v")]
    serialization_info: SerializationInfo,
    #[serde(rename = "d")]
    digest: SelfAddressingPrefix,
    #[serde(flatten)]
    data: D,
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> KeriEvent<D> {
	pub fn new(
        event: D,
        format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<Self, Error> {
        let dummy_event = DummyEvent::dummy_event(derivation, format, event)?;

        let sai = derivation.derive(&dummy_event.serialize()?);
        Ok(Self { serialization_info: dummy_event.serialization_info, digest: sai, data: event })

    }
}