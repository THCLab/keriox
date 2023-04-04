use crate::{
    error::Error,
    event::sections::key_config::nxt_commitment,
    event::{
        event_data::{
            delegated::DelegatedInceptionEvent, interaction::InteractionEvent,
            rotation::RotationEvent,
        },
        sections::{
            key_config::NextKeysData, threshold::SignatureThreshold, RotationWitnessConfig,
        },
    },
    event::{
        event_data::{inception::InceptionEvent, EventData},
        receipt::Receipt,
        sections::seal::Seal,
        sections::InceptionWitnessConfig,
        sections::KeyConfig,
        KeyEvent,
    },
    keys::PublicKey,
    prefix::{BasicPrefix, IdentifierPrefix},
};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};
use version::serialization_info::SerializationFormats;

use super::{msg::KeriEvent, EventTypeTag};

pub struct EventMsgBuilder {
    event_type: EventTypeTag,
    prefix: IdentifierPrefix,
    sn: u64,
    key_threshold: SignatureThreshold,
    next_key_threshold: SignatureThreshold,
    keys: Vec<BasicPrefix>,
    next_keys: Vec<BasicPrefix>,
    next_keys_hashes: Option<Vec<SelfAddressingIdentifier>>,
    prev_event: SelfAddressingIdentifier,
    data: Vec<Seal>,
    delegator: IdentifierPrefix,
    witness_threshold: SignatureThreshold,
    witnesses: Vec<BasicPrefix>,
    witness_to_add: Vec<BasicPrefix>,
    witness_to_remove: Vec<BasicPrefix>,
    format: SerializationFormats,
    derivation: HashFunction,
}

impl EventMsgBuilder {
    pub fn new(event_type: EventTypeTag) -> Self {
        let mut rng = OsRng {};
        let kp = Keypair::generate(&mut rng);
        let nkp = Keypair::generate(&mut rng);
        let pk = PublicKey::new(kp.public.to_bytes().to_vec());
        let npk = PublicKey::new(nkp.public.to_bytes().to_vec());
        let hash_function: HashFunction = HashFunctionCode::Blake3_256.into();
        let basic_pref = BasicPrefix::Ed25519(pk);
        EventMsgBuilder {
            event_type,
            prefix: IdentifierPrefix::default(),
            keys: vec![basic_pref],
            next_keys: vec![BasicPrefix::Ed25519(npk)],
            key_threshold: SignatureThreshold::default(),
            next_key_threshold: SignatureThreshold::default(),
            sn: 1,
            prev_event: hash_function.derive(&[0u8; 32]),
            data: vec![],
            delegator: IdentifierPrefix::default(),
            witness_threshold: SignatureThreshold::Simple(0),
            witnesses: vec![],
            witness_to_add: vec![],
            witness_to_remove: vec![],
            format: SerializationFormats::JSON,
            derivation: hash_function,
            next_keys_hashes: None,
        }
    }

    pub fn with_prefix(self, prefix: &IdentifierPrefix) -> Self {
        EventMsgBuilder {
            prefix: prefix.clone(),
            ..self
        }
    }

    pub fn with_keys(self, keys: Vec<BasicPrefix>) -> Self {
        EventMsgBuilder { keys, ..self }
    }

    pub fn with_next_keys(self, next_keys: Vec<BasicPrefix>) -> Self {
        EventMsgBuilder { next_keys, ..self }
    }

    pub fn with_next_keys_hashes(self, next_keys: Vec<SelfAddressingIdentifier>) -> Self {
        EventMsgBuilder {
            next_keys_hashes: Some(next_keys),
            ..self
        }
    }

    pub fn with_sn(self, sn: u64) -> Self {
        EventMsgBuilder { sn, ..self }
    }
    pub fn with_previous_event(self, prev_event: &SelfAddressingIdentifier) -> Self {
        EventMsgBuilder {
            prev_event: prev_event.clone(),
            ..self
        }
    }

    pub fn with_seal(mut self, seals: Vec<Seal>) -> Self {
        self.data.extend(seals);
        EventMsgBuilder { ..self }
    }

    pub fn with_delegator(self, delegator: &IdentifierPrefix) -> Self {
        EventMsgBuilder {
            delegator: delegator.clone(),
            ..self
        }
    }

    pub fn with_threshold(self, threshold: &SignatureThreshold) -> Self {
        EventMsgBuilder {
            key_threshold: threshold.clone(),
            ..self
        }
    }

    pub fn with_next_threshold(self, threshold: &SignatureThreshold) -> Self {
        EventMsgBuilder {
            next_key_threshold: threshold.clone(),
            ..self
        }
    }

    pub fn with_witness_list(self, witnesses: &[BasicPrefix]) -> Self {
        EventMsgBuilder {
            witnesses: witnesses.to_vec(),
            ..self
        }
    }

    pub fn with_witness_to_add(self, witness_to_add: &[BasicPrefix]) -> Self {
        EventMsgBuilder {
            witness_to_add: witness_to_add.to_vec(),
            ..self
        }
    }

    pub fn with_witness_to_remove(self, witness_to_remove: &[BasicPrefix]) -> Self {
        EventMsgBuilder {
            witness_to_remove: witness_to_remove.to_vec(),
            ..self
        }
    }

    pub fn with_witness_threshold(self, witness_threshold: &SignatureThreshold) -> Self {
        EventMsgBuilder {
            witness_threshold: witness_threshold.clone(),
            ..self
        }
    }

    pub fn build(self) -> Result<KeriEvent<KeyEvent>, Error> {
        let next_key_hash = if let Some(hashes) = self.next_keys_hashes {
            NextKeysData {
                threshold: self.next_key_threshold,
                next_key_hashes: hashes,
            }
        } else {
            nxt_commitment(self.next_key_threshold, &self.next_keys, &self.derivation)
        };
        let key_config = KeyConfig::new(self.keys, next_key_hash, Some(self.key_threshold));
        let prefix = if self.prefix == IdentifierPrefix::default() {
            let icp_data = InceptionEvent::new(key_config.clone(), None, None)
                .incept_self_addressing(self.derivation.clone(), self.format)?;
            icp_data.data.get_prefix()
        } else {
            self.prefix
        };

        Ok(match self.event_type {
            EventTypeTag::Icp => {
                let icp_event = InceptionEvent {
                    key_config,
                    witness_config: InceptionWitnessConfig {
                        tally: self.witness_threshold,
                        initial_witnesses: self.witnesses,
                    },
                    inception_configuration: vec![],
                    data: vec![],
                };

                match prefix {
                    IdentifierPrefix::Basic(_) => {
                        KeyEvent::new(prefix, 0, EventData::Icp(icp_event))
                            .to_message(self.format, self.derivation)?
                    }
                    IdentifierPrefix::SelfAddressing(_) => {
                        icp_event.incept_self_addressing(self.derivation, self.format)?
                    }
                    _ => todo!(),
                }
            }

            EventTypeTag::Rot => KeyEvent::new(
                prefix,
                self.sn,
                EventData::Rot(RotationEvent {
                    previous_event_hash: self.prev_event,
                    key_config,
                    witness_config: RotationWitnessConfig {
                        tally: self.witness_threshold,
                        prune: self.witness_to_remove,
                        graft: self.witness_to_add,
                    },
                    data: self.data,
                }),
            )
            .to_message(self.format, self.derivation)?,
            EventTypeTag::Ixn => KeyEvent::new(
                prefix,
                self.sn,
                EventData::Ixn(InteractionEvent {
                    previous_event_hash: self.prev_event,
                    data: self.data,
                }),
            )
            .to_message(self.format, self.derivation)?,
            EventTypeTag::Dip => {
                let icp_data = InceptionEvent {
                    key_config,
                    witness_config: InceptionWitnessConfig {
                        tally: self.witness_threshold,
                        initial_witnesses: self.witnesses,
                    },
                    inception_configuration: vec![],
                    data: vec![],
                };
                DelegatedInceptionEvent {
                    inception_data: icp_data,
                    delegator: self.delegator,
                }
                .incept_self_addressing(self.derivation, self.format)?
            }
            EventTypeTag::Drt => {
                let rotation_data = RotationEvent {
                    previous_event_hash: self.prev_event,
                    key_config,
                    witness_config: RotationWitnessConfig::default(),
                    data: self.data,
                };
                KeyEvent::new(prefix, self.sn, EventData::Drt(rotation_data))
                    .to_message(self.format, self.derivation)?
            }
            _ => return Err(Error::SemanticError("Not key event".into())),
        })
    }
}

pub struct ReceiptBuilder {
    format: SerializationFormats,
    receipted_event: KeriEvent<KeyEvent>,
}

impl Default for ReceiptBuilder {
    fn default() -> Self {
        let default_event = EventMsgBuilder::new(EventTypeTag::Icp).build().unwrap();
        Self {
            format: SerializationFormats::JSON,
            receipted_event: default_event,
        }
    }
}

impl ReceiptBuilder {
    pub fn with_format(self, format: SerializationFormats) -> Self {
        Self { format, ..self }
    }

    pub fn with_receipted_event(self, receipted_event: KeriEvent<KeyEvent>) -> Self {
        Self {
            receipted_event,
            ..self
        }
    }

    pub fn build(&self) -> Result<Receipt, Error> {
        let prefix = self.receipted_event.data.get_prefix();
        let sn = self.receipted_event.data.get_sn();
        let receipted_event_digest = self.receipted_event.get_digest();
        Ok(Receipt::new(
            self.format,
            receipted_event_digest,
            prefix,
            sn,
        ))
    }
}

#[test]
fn test_multisig_prefix_derivation() {
    // Keys taken from keripy: keripy/tests/core/test_eventing.py::test_multisig_digprefix (line 2255)
    let expected_event = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}"#;

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
    let next_keys: Vec<BasicPrefix> = vec![
        "DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE"
            .parse()
            .unwrap(),
        "DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV"
            .parse()
            .unwrap(),
        "DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"
            .parse()
            .unwrap(),
    ];

    let msg_builder = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(keys)
        .with_next_keys(next_keys)
        .with_threshold(&SignatureThreshold::Simple(2))
        .with_next_threshold(&SignatureThreshold::Simple(2));
    let msg = msg_builder.build().unwrap();

    assert_eq!(expected_event.to_vec(), msg.encode().unwrap());
}
