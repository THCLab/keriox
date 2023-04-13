use sad_macros::SAD;
use said::{derivation::HashFunction, derivation::HashFunctionCode, SelfAddressingIdentifier, sad::SAD};
use serde::{Deserialize, Serialize, Serializer};
use version::serialization_info::{SerializationFormats, SerializationInfo};

use crate::error::Error;

use super::{dummy_event::DummyEvent, Typeable};

#[derive(Deserialize, Debug, Clone, PartialEq, SAD)]
pub struct KeriEvent<D: Serialize + Clone> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
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

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> KeriEvent<D> {
    pub fn get_digest(&self) -> SelfAddressingIdentifier {
        self.digest.clone().unwrap()
    }

    pub fn dummy_event(&self) -> std::result::Result<Vec<u8>, Error> {
        DummyEvent::dummy_event(
            self.data.clone(),
            self.serialization_info.kind,
            &(&self.digest.as_ref().unwrap().derivation).into(),
        )?
        .encode()
    }

    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy: Vec<u8> = self.dummy_event()?;
        self.get_digest()
            .verify_binding(&dummy)
            .then_some(())
            .ok_or(Error::IncorrectDigest)
    }
}

impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> KeriEvent<D> {
    pub fn new(
        format: SerializationFormats,
        derivation: HashFunction,
        event: D,
    ) -> Result<Self, Error> {
        let tmp_serialization_info = SerializationInfo::new_empty("KERI".to_string(), format);
        
        let mut tmp_self = Self { serialization_info: tmp_serialization_info, digest: None, data: event };
        let encoded = tmp_self.derivative(&(&derivation).into(), &format);
        println!("In KeriEvent new: {}", encoded);

        let event_len = encoded.len();
        tmp_self.serialization_info.size = event_len;
        let keri_event = tmp_self.compute_digest((&derivation).into(), format);
        Ok(keri_event)

        // let dummy_event = DummyEvent::dummy_event(event.clone(), format, &(&derivation).into())?;

        // let sai = derivation.derive(&dummy_event.encode()?);
        // Ok(Self {
        //     serialization_info: dummy_event.serialization_info,
        //     digest: sai,
        //     data: event,
        // })
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.serialize(&self).unwrap())
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
            digest: SelfAddressingIdentifier,

            #[serde(flatten)]
            event: D,
        }
        impl<T: Serialize, D: Serialize + Typeable<TypeTag = T> + Clone> From<&KeriEvent<D>>
            for TypedEventMessage<T, D>
        {
            fn from(em: &KeriEvent<D>) -> Self {
                TypedEventMessage {
                    v: em.serialization_info.clone(),
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
