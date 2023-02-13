use serde::{Deserialize, Serialize, Serializer};
use version::{
    serialization_info::{SerializationFormats, SerializationInfo},
    Versional,
};

use crate::{
    error::Error,
    sai::{derivation::SelfAddressing, sad::SAD, SelfAddressingPrefix},
};

use super::{dummy_event::DummyEvent, Typeable};

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct KeriEvent<D> {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    #[serde(rename = "d")]
    pub digest: SelfAddressingPrefix,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> SAD for KeriEvent<D> {
    fn get_digest(&self) -> SelfAddressingPrefix {
        self.digest.clone()
    }

    fn dummy_event(&self) -> Result<Vec<u8>, Error> {
        DummyEvent::dummy_event(
            self.data.clone(),
            self.serialization_info.kind,
            &self.digest.derivation,
        )?
        .serialize()
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> Versional for KeriEvent<D> {
    fn get_version_str(&self) -> SerializationInfo {
        self.serialization_info
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> KeriEvent<D> {
    pub fn new(
        format: SerializationFormats,
        derivation: SelfAddressing,
        event: D,
    ) -> Result<Self, Error> {
        let dummy_event = DummyEvent::dummy_event(event.clone(), format, &derivation)?;

        let sai = derivation.derive(&dummy_event.serialize()?);
        Ok(Self {
            serialization_info: dummy_event.serialization_info,
            digest: sai,
            data: event,
        })
    }
}

impl<T: Serialize, D: Typeable<TypeTag = T> + Serialize + Clone> Serialize for KeriEvent<D> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Helper struct for adding `t` field to EventMessage serialization
        #[derive(Serialize)]
        struct TypedEventMessage<T, D> {
            #[serde(rename = "v")]
            v: SerializationInfo,

            #[serde(rename = "t")]
            event_type: T,

            #[serde(rename = "d")]
            digest: SelfAddressingPrefix,

            #[serde(flatten)]
            event: D,
        }
        impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> From<&KeriEvent<D>>
            for TypedEventMessage<T, D>
        {
            fn from(em: &KeriEvent<D>) -> Self {
                TypedEventMessage {
                    v: em.serialization_info,
                    event_type: em.data.get_type(),
                    digest: em.get_digest(),
                    event: em.data.clone(),
                }
            }
        }

        let tem: TypedEventMessage<_, _> = self.into();
        tem.serialize(serializer)
    }
}
