use super::EventData;
use super::InceptionEvent;
use crate::event_message::dummy_event::DummyInceptionEvent;
use crate::event_message::msg::KeriEvent;
use crate::event_message::Typeable;
use crate::{
    error::Error,
    event::{KeyEvent, SerializationFormats},
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState},
};
use said::derivation::HashFunction;
use said::derivation::HashFunctionCode;
use said::sad::SAD;
use serde::{Deserialize, Serialize};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct DelegatedInceptionEvent {
    #[serde(flatten)]
    pub inception_data: InceptionEvent,

    #[serde(rename = "di")]
    pub delegator: IdentifierPrefix,
}

impl DelegatedInceptionEvent {
    /// Incept Self Addressing
    ///
    /// Takes the inception data and creates an EventMessage based on it, with
    /// using the given format and deriving a Self Addressing Identifier with the
    /// given derivation method
    pub fn incept_self_addressing(
        self,
        derivation: HashFunction,
        format: SerializationFormats,
    ) -> Result<KeriEvent<KeyEvent>, Error> {
        let code: HashFunctionCode = derivation.into();
        let mut dummy_event =
            DummyInceptionEvent::dummy_delegated_inception_data(self.clone(), &code, format)?;
        dummy_event.compute_digest(&code, &format);
        let digest = dummy_event.prefix.unwrap();
        let event = KeyEvent::new(
            IdentifierPrefix::self_addressing(digest.clone()),
            0,
            EventData::Dip(self),
        );
        Ok(KeriEvent {
            serialization_info: dummy_event.serialization_info,
            event_type: event.get_type(),
            digest: Some(digest.into()),
            data: event,
        })
    }
}

impl EventSemantics for DelegatedInceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        Ok(IdentifierState {
            delegator: Some(self.delegator.clone()),
            ..self.inception_data.apply_to(state)?
        })
    }
}

#[test]
fn test_delegated_inception_data_derivation() -> Result<(), Error> {
    use crate::event::sections::{
        key_config::{nxt_commitment, KeyConfig},
        threshold::SignatureThreshold,
    };
    use crate::prefix::BasicPrefix;
    use cesrox::primitives::CesrPrimitive;
    use said::derivation::HashFunctionCode;

    // data taken from keripy/tests/core/test_delegation.py
    let keys: Vec<BasicPrefix> = vec!["DLitcfMnabnLt-PNCaXdVwX45wsG93Wd8eW9QiZrlKYQ"
        .parse()
        .unwrap()];
    let next_keys: Vec<BasicPrefix> = vec!["DE3-kGVqHrdeeKPcL83jLjYS0Ea_CWgFHogusIwf-P9P"
        .parse()
        .unwrap()];

    let next_key_hash = nxt_commitment(
        SignatureThreshold::Simple(1),
        &next_keys,
        &HashFunctionCode::Blake3_256.into(),
    );
    let key_config = KeyConfig::new(keys, next_key_hash, Some(SignatureThreshold::Simple(1)));
    let dip_data = DelegatedInceptionEvent {
        inception_data: InceptionEvent::new(key_config.clone(), None, None),
        delegator: "EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH".parse()?,
    }
    .incept_self_addressing(
        HashFunctionCode::Blake3_256.into(),
        SerializationFormats::JSON,
    )?;

    let dip_digest = dip_data.digest()?;
    assert_eq!(
        "EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj",
        dip_data.data.get_prefix().to_str()
    );
    assert_eq!(
        "EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj",
        dip_digest.to_str()
    );
    assert_eq!("KERI10JSON00015f_", dip_data.serialization_info.to_str());
    assert!(dip_digest.verify_binding(&dip_data.to_derivation_data().unwrap()));

    Ok(())
}
