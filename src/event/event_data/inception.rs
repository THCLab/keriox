use super::{
    super::sections::{InceptionWitnessConfig, KeyConfig},
    EventData,
};
use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::Seal, Event},
    event_message::{
        dummy_event::DummyInceptionEvent, key_event_message::KeyEvent,
        serialization_info::SerializationFormats, EventMessage, SaidEvent,
    },
    prefix::IdentifierPrefix,
    state::{EventSemantics, IdentifierState, LastEstablishmentData},
};
use serde::{Deserialize, Serialize};

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
    ) -> Result<EventMessage<KeyEvent>, Error> {
        let dummy_event =
            DummyInceptionEvent::dummy_inception_data(self.clone(), &derivation, format)?;
        let digest = derivation.derive(&dummy_event.serialize()?);
        let event = Event::new(
            IdentifierPrefix::SelfAddressing(digest.clone()),
            0,
            EventData::Icp(self),
        );
        Ok(EventMessage {
            serialization_info: dummy_event.serialization_info,
            event: SaidEvent::new(digest, event),
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
        key_config::KeyConfig,
        threshold::SignatureThreshold,
        key_config::NextKeysData
    };
    use crate::event_message::Digestible;
    use crate::prefix::{BasicPrefix, Prefix, SelfAddressingPrefix};

    let keys: Vec<BasicPrefix> = vec![
        "DRd2QdFHY2ymPlzOwW8o5r5mcbMwwUbkwtoGV7X1on2M"
            .parse()
            .unwrap(),
        "DvhIXMDz2Wz9q4iohJ_hRtJAbE09z3LxnZSs8Nm6kSww"
            .parse()
            .unwrap(),
        "DRHHGMFBQPicaJqKgGWqDyqmRGMksYx7rs491WwcVqtA"
            .parse()
            .unwrap(),
    ];
    let next_keys_hashes: Vec<SelfAddressingPrefix> = vec![
        "ExKDRQLyYUS3O1xme1pbKenP73WqpbKTMopvUSQFRRSw"
            .parse()
            .unwrap(),
        "E2e7tLvlVlER4kkV3bw36SN8Gz3fJ-3QR2xadxKyed10"
            .parse()
            .unwrap(),
        "Ekhos3Fx8IfwKdfQrfZ_FicfrYiXmvZodQcHV3KNOSlU"
            .parse()
            .unwrap(),
    ];

    let next_keys_data = NextKeysData { threshold: SignatureThreshold::Simple(2), next_key_hashes: next_keys_hashes };
    let key_config = KeyConfig::new(keys, next_keys_data, Some(SignatureThreshold::Simple(2)));
    let icp_data = InceptionEvent::new(key_config.clone(), None, None)
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

    assert_eq!(
        "EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY",
        icp_data.event.get_prefix().to_str()
    );
    assert_eq!(
        "EfFRznBFTCjE6L4Muo0mJ3rPpf-31ytLhe7ZW5FGLpaY",
        icp_data.event.get_digest().to_str()
    );

    Ok(())
}
