use said::version::{format::SerializationFormats, SerializationInfo};
use said::{
    derivation::HashFunction, derivation::HashFunctionCode, sad::SAD, SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};

use crate::database::redb::rkyv_adapter::said_wrapper::{SAIDef, SaidValue};
use crate::database::redb::rkyv_adapter::serialization_info_wrapper::SerializationInfoDef;
use crate::error::Error;

use super::{EventTypeTag, Typeable};

pub type KeriEvent<D> = TypedEvent<EventTypeTag, D>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, SAD)]
// #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
// #[rkyv(
//     compare(PartialEq),
//     derive(Debug),
// )]
pub struct TypedEvent<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    // #[rkyv(with = SerializationInfoDef)]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "t")]
    pub event_type: T,

    /// Digest of the event
    ///
    /// While computing the digest, this field is replaced with sequence of `#`,
    /// its length depends on derivation type. Then it is replaced by computed
    /// SAI.
    #[said]
    #[serde(rename = "d")]
    // #[rkyv(with = SAIDef)]
    pub digest: Option<SelfAddressingIdentifier>,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize + Clone, D: Serialize + Typeable<TypeTag = T> + Clone> TypedEvent<T, D> {
    pub fn digest(&self) -> Result<SelfAddressingIdentifier, Error> {
        self.digest.to_owned().ok_or(Error::EventDigestError)
    }

    pub fn check_digest(&self) -> Result<(), Error> {
        let event_digest = self.digest()?;
        let hash_function_code = event_digest.derivation.to_owned().into();
        let dummy = self.derivation_data(&hash_function_code, &self.serialization_info.kind);
        event_digest
            .verify_binding(&dummy)
            .then_some(())
            .ok_or(Error::IncorrectDigest)
    }

    pub fn new(format: SerializationFormats, derivation: HashFunction, event: D) -> Self {
        let tmp_serialization_info = SerializationInfo::new_empty("KERI".to_string(), 1, 0, format);

        let mut tmp_self = Self {
            serialization_info: tmp_serialization_info,
            event_type: event.get_type(),
            digest: None,
            data: event,
        };
        let hash_function = derivation.into();
        let encoded = tmp_self.derivation_data(&hash_function, &format);

        let event_len = encoded.len();
        tmp_self.serialization_info.size = event_len;
        tmp_self.compute_digest(&hash_function, &format);
        tmp_self
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.serialize(&self).unwrap())
    }
}
