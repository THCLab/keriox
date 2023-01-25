use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    EventData,
};
use crate::{
    error::Error,
    event::{sections::seal::Seal, KeyEvent},
    event_message::{dummy_event::DummyInceptionEvent, msg::KeriEvent},
    prefix::IdentifierPrefix,
    sai::{derivation::SelfAddressing, sad::SAD},
    state::{EventSemantics, IdentifierState, LastEstablishmentData},
};
use serde::{Deserialize, Serialize};
use version::serialization_info::SerializationFormats;

/// Inception Event
///
/// Describes the inception (icp) event data,
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct InceptionEvent {
    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: InceptionWitnessConfig,

    #[serde(rename = "c")]
    pub inception_configuration: Vec<String>,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl InceptionEvent {
    pub fn new(
        key_config: KeyConfig,
        witness_config: Option<InceptionWitnessConfig>,
        inception_config: Option<Vec<String>>,
    ) -> Self {
        Self {
            key_config,
            witness_config: witness_config.map_or_else(InceptionWitnessConfig::default, |w| w),
            inception_configuration: inception_config.map_or_else(Vec::new, |c| c),
            data: vec![],
        }
    }

    /// Incept Self Addressing
    ///
    /// Takes the inception data and creates an EventMessage based on it, with
    /// using the given format and deriving a Self Addressing Identifier with the
    /// given derivation method
    pub fn incept_self_addressing(
        self,
        derivation: SelfAddressing,
        format: SerializationFormats,
    ) -> Result<KeriEvent<KeyEvent>, Error> {
        let dummy_event =
            DummyInceptionEvent::dummy_inception_data(self.clone(), derivation.clone(), format)?;
        let digest = derivation.derive(&dummy_event.serialize()?);
        let event = KeyEvent::new(
            IdentifierPrefix::SelfAddressing(digest.clone()),
            0,
            EventData::Icp(self),
        );
        Ok(KeriEvent {
            serialization_info: dummy_event.serialization_info,
            digest,
            data: event,
        })
    }
}

impl EventSemantics for InceptionEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let last_est = LastEstablishmentData {
            sn: state.sn,
            digest: state.last_event_digest.clone(),
            br: vec![],
            ba: vec![],
        };

        Ok(IdentifierState {
            current: self.key_config.clone(),
            witness_config: self.witness_config.clone().into(),
            last_est,
            ..state
        })
    }
}

#[test]
fn test_inception_data_derivation() -> Result<(), Error> {
    use crate::event::sections::{
        key_config::KeyConfig, key_config::NextKeysData, threshold::SignatureThreshold,
    };
    use crate::prefix::BasicPrefix;
    use crate::sai::SelfAddressingPrefix;
    use cesrox::primitives::CesrPrimitive;

    let keys: Vec<BasicPrefix> = vec![
        "DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
            .parse()
            .unwrap(),
        "DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS"
            .parse()
            .unwrap(),
        "DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"
            .parse()
            .unwrap(),
    ];
    let next_keys_hashes: Vec<SelfAddressingPrefix> = vec![
        "EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8"
            .parse()
            .unwrap(),
        "EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss"
            .parse()
            .unwrap(),
        "EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"
            .parse()
            .unwrap(),
    ];

    let next_keys_data = NextKeysData {
        threshold: SignatureThreshold::Simple(2),
        next_key_hashes: next_keys_hashes,
    };
    let key_config = KeyConfig::new(keys, next_keys_data, Some(SignatureThreshold::Simple(2)));
    let icp_data = InceptionEvent::new(key_config.clone(), None, None)
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

    assert_eq!(
        "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen",
        icp_data.data.get_prefix().to_str()
    );
    assert_eq!(
        "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen",
        icp_data.get_digest().to_str()
    );

    Ok(())
}
