use sad_macros::SAD;
use said::{
    derivation::HashFunction, derivation::HashFunctionCode, sad::SAD, SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};
use version::serialization_info::{SerializationFormats, SerializationInfo};

use crate::error::Error;

use super::{EventTypeTag, Typeable};

pub type KeriEvent<D> = TypedEvent<EventTypeTag, D>;

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, SAD)]
pub struct TypedEvent<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
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
    pub digest: Option<SelfAddressingIdentifier>,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize + Clone, D: Serialize + Typeable<TypeTag = T> + Clone> TypedEvent<T, D> {
    pub fn get_digest(&self) -> SelfAddressingIdentifier {
        self.digest.clone().unwrap()
    }

    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy = self.derivative(
            &(&self.get_digest().derivation).into(),
            &self.serialization_info.kind,
        );
        let dummy = dummy.as_bytes().to_vec();
        Ok(self
            .get_digest()
            .verify_binding(&dummy)
            .then_some(())
            .unwrap())
        // .ok_or(Error::IncorrectDigest)
    }

    pub fn new(
        format: SerializationFormats,
        derivation: HashFunction,
        event: D,
    ) -> Result<Self, Error> {
        let tmp_serialization_info = SerializationInfo::new_empty("KERI".to_string(), format);

        let mut tmp_self = Self {
            serialization_info: tmp_serialization_info,
            event_type: event.get_type(),
            digest: None,
            data: event,
        };
        let encoded = tmp_self.derivative(&(&derivation).into(), &format);
        println!("In KeriEvent new: {}", encoded);

        let event_len = encoded.len();
        tmp_self.serialization_info.size = event_len;
        let keri_event = tmp_self.compute_digest((&derivation).into(), format);
        Ok(keri_event)
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.serialize(&self).unwrap())
    }
}
