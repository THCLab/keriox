use cesrox::primitives::codes::self_addressing::dummy_prefix;
use sai::{sad::SAD, SelfAddressingPrefix};
use version::serialization_info::SerializationInfo;

use crate::{
    error::Error,
    event::{event_data::EventData, sections::seal::SourceSeal, KeyEvent},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
    state::{EventSemantics, IdentifierState},
};

use super::{
    dummy_event::{DummyEvent, DummyInceptionEvent},
    msg::KeriEvent,
    signature::Nontransferable,
    signed_event_message::SignedEventMessage,
    EventTypeTag, Typeable,
};

impl KeyEvent {
    pub fn get_sn(&self) -> u64 {
        self.sn
    }
    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.prefix.clone()
    }
    pub fn get_event_data(&self) -> EventData {
        self.event_data.clone()
    }
}

impl From<KeriEvent<KeyEvent>> for DummyEvent<EventTypeTag, KeyEvent> {
    fn from(em: KeriEvent<KeyEvent>) -> Self {
        DummyEvent {
            serialization_info: SerializationInfo::default(),
            event_type: em.data.get_type(),
            digest: dummy_prefix(&em.get_digest().derivation.into()),
            data: em.data,
        }
    }
}

impl KeriEvent<KeyEvent> {
    pub fn sign(
        &self,
        sigs: Vec<AttachedSignaturePrefix>,
        witness_sigs: Option<Vec<Nontransferable>>,
        delegator_seal: Option<SourceSeal>,
    ) -> SignedEventMessage {
        SignedEventMessage::new(self, sigs, witness_sigs, delegator_seal)
    }

    pub fn compare_digest(&self, sai: &SelfAddressingPrefix) -> Result<bool, Error> {
        let self_dig = self.get_digest();
        if self_dig.derivation == sai.derivation {
            Ok(&self_dig == sai)
        } else {
            Ok(sai.verify_binding(&self.to_derivation_data()?))
        }
    }

    fn to_derivation_data(&self) -> Result<Vec<u8>, Error> {
        Ok(match self.data.get_event_data() {
            EventData::Icp(icp) => DummyInceptionEvent::dummy_inception_data(
                icp,
                self.get_digest().derivation,
                self.serialization_info.kind,
            )?
            .encode()?,
            EventData::Dip(dip) => DummyInceptionEvent::dummy_delegated_inception_data(
                dip,
                self.get_digest().derivation,
                self.serialization_info.kind,
            )?
            .encode()?,
            _ => {
                let dummy_event: DummyEvent<_, _> = self.clone().into();
                dummy_event.encode()?
            }
        })
    }
}

impl EventSemantics for KeriEvent<KeyEvent> {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let check_event_digest = |ev: &KeriEvent<KeyEvent>| -> Result<(), Error> {
            ev.compare_digest(&self.get_digest())?
                .then(|| ())
                .ok_or(Error::IncorrectDigest)
        };
        // Update state.last with serialized current event message.
        match self.data.get_event_data() {
            EventData::Icp(_) | EventData::Dip(_) => {
                if verify_identifier_binding(self)? {
                    self.data.apply_to(IdentifierState {
                        last_event_digest: self.get_digest(),
                        ..state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Invalid Identifier Prefix Binding".into(),
                    ))
                }
            }
            EventData::Rot(ref rot) => {
                check_event_digest(self)?;
                if state.delegator.is_some() {
                    Err(Error::SemanticError(
                        "Applying non-delegated rotation to delegated state.".into(),
                    ))
                } else {
                    // Event may be out of order or duplicated, so before checking
                    // previous event hash binding and update state last, apply it
                    // to the state. It will return EventOutOfOrderError or
                    // EventDuplicateError in that cases.
                    self.data.apply_to(state.clone()).and_then(|next_state| {
                        if rot.previous_event_hash.eq(&state.last_event_digest) {
                            Ok(IdentifierState {
                                last_event_digest: self.get_digest(),
                                ..next_state
                            })
                        } else {
                            Err(Error::SemanticError(
                                "Last event does not match previous event".into(),
                            ))
                        }
                    })
                }
            }
            EventData::Drt(ref drt) => self.data.apply_to(state.clone()).and_then(|next_state| {
                check_event_digest(self)?;
                if state.delegator.is_none() {
                    Err(Error::SemanticError(
                        "Applying delegated rotation to non-delegated state.".into(),
                    ))
                } else if drt.previous_event_hash.eq(&state.last_event_digest) {
                    Ok(IdentifierState {
                        last_event_digest: self.get_digest(),
                        ..next_state
                    })
                } else {
                    Err(Error::SemanticError(
                        "Last event does not match previous event".into(),
                    ))
                }
            }),
            EventData::Ixn(ref inter) => {
                check_event_digest(self)?;
                self.data.apply_to(state.clone()).and_then(|next_state| {
                    if inter.previous_event_hash.eq(&state.last_event_digest) {
                        Ok(IdentifierState {
                            last_event_digest: self.get_digest(),
                            ..next_state
                        })
                    } else {
                        Err(Error::SemanticError(
                            "Last event does not match previous event".to_string(),
                        ))
                    }
                })
            }
        }
    }
}

pub fn verify_identifier_binding(icp_event: &KeriEvent<KeyEvent>) -> Result<bool, Error> {
    let event_data = &icp_event.data.get_event_data();
    match event_data {
        EventData::Icp(icp) => match &icp_event.data.get_prefix() {
            IdentifierPrefix::Basic(bp) => Ok(icp.key_config.public_keys.len() == 1
                && bp.eq(icp
                    .key_config
                    .public_keys
                    .first()
                    .ok_or_else(|| Error::SemanticError("Missing public key".into()))?)),
            IdentifierPrefix::SelfAddressing(sap) => {
                Ok(icp_event.compare_digest(sap)? && icp_event.get_digest().eq(sap))
            }
            IdentifierPrefix::SelfSigning(_ssp) => todo!(),
        },
        EventData::Dip(_dip) => match &icp_event.data.get_prefix() {
            IdentifierPrefix::SelfAddressing(sap) => icp_event.compare_digest(sap),
            _ => todo!(),
        },
        _ => Err(Error::SemanticError("Not an ICP or DIP event".into())),
    }
}
