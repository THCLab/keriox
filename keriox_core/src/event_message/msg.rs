use said::version::{format::SerializationFormats, SerializationInfo};
use said::{
    derivation::HashFunction, derivation::HashFunctionCode, sad::SAD, SelfAddressingIdentifier,
};
use serde::{Deserialize, Serialize};

use super::{EventTypeTag, Typeable};
use crate::database::rkyv_adapter::said_wrapper::SaidValue;
use crate::database::rkyv_adapter::serialization_info_wrapper::SerializationInfoDef;
use crate::error::Error;

pub type KeriEvent<D> = TypedEvent<EventTypeTag, D>;

#[derive(
    Deserialize,
    Serialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct TypedEvent<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> {
    /// Serialization Information
    ///
    /// Encodes the version, size and serialization format of the event
    #[serde(rename = "v")]
    #[rkyv(with = SerializationInfoDef)]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "t")]
    pub event_type: T,

    /// Digest of the event
    ///
    /// While computing the digest, this field is replaced with sequence of `#`,
    /// its length depends on derivation type. Then it is replaced by computed
    /// SAI.
    #[serde(rename = "d")]
    pub(crate) digest: Option<SaidValue>,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize + Clone, D: Serialize + Typeable<TypeTag = T> + Clone> TypedEvent<T, D> {
    pub fn digest(&self) -> Result<SelfAddressingIdentifier, Error> {
        self.digest
            .to_owned()
            .ok_or(Error::EventDigestError)
            .map(|said| said.into())
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

impl<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> SAD for TypedEvent<T, D> {
    fn compute_digest(&mut self, derivation: &HashFunctionCode, format: &SerializationFormats) {
        let der_data = self.derivation_data(derivation, format);
        let said = HashFunction::from(derivation.clone())
            .derive(&der_data)
            .into();
        self.digest = Some(said);
    }

    fn derivation_data(
        &self,
        derivation: &HashFunctionCode,
        format: &SerializationFormats,
    ) -> Vec<u8> {
        let tmp_event = DummyTypedEvent::convert(self.clone(), derivation.clone());
        format.encode(&tmp_event).unwrap()
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct DummyTypedEvent<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "t")]
    pub event_type: T,

    #[serde(rename = "d")]
    digest: String,
    #[serde(flatten)]
    pub data: D,
}

impl<T: Serialize + Clone, D: Serialize + Clone + Typeable<TypeTag = T>> DummyTypedEvent<T, D> {
    fn convert(value: TypedEvent<T, D>, hash_function: HashFunctionCode) -> Self {
        Self {
            serialization_info: value.serialization_info,
            event_type: value.event_type,
            digest: "#".repeat(HashFunction::from(hash_function).get_len()),
            data: value.data,
        }
    }
}

#[test]
fn test_rkyv_serialization() {
    use crate::event::KeyEvent;
    use rkyv::rancor::Failure;
    let icp_raw: &[u8] = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}"#;

    let event: KeriEvent<KeyEvent> = serde_json::from_slice(icp_raw).unwrap();

    let bytes = rkyv::to_bytes::<rkyv::rancor::Failure>(&event).unwrap();

    let archived: &ArchivedTypedEvent<EventTypeTag, KeyEvent> =
        rkyv::access::<_, Failure>(&bytes).unwrap();

    let deserialized: KeriEvent<KeyEvent> =
        rkyv::deserialize::<KeriEvent<KeyEvent>, Failure>(archived).unwrap();
    assert_eq!(deserialized, event);
}
