use said::{sad::SAD, SelfAddressingIdentifier};

use crate::{
    error::Error,
    event::{event_data::EventData, sections::seal::SourceSeal, KeyEvent},
    prefix::{IdentifierPrefix, IndexedSignature},
    state::{EventSemantics, IdentifierState},
};

use super::{
    dummy_event::DummyInceptionEvent, msg::KeriEvent, signature::Nontransferable,
    signed_event_message::SignedEventMessage, EventTypeTag,
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

impl KeriEvent<KeyEvent> {
    pub fn sign(
        &self,
        sigs: Vec<IndexedSignature>,
        witness_sigs: Option<Vec<Nontransferable>>,
        delegator_seal: Option<SourceSeal>,
    ) -> SignedEventMessage {
        SignedEventMessage::new(self, sigs, witness_sigs, delegator_seal)
    }

    pub fn compare_digest(&self, sai: &SelfAddressingIdentifier) -> Result<bool, Error> {
        let self_dig = self.get_digest();
        if self_dig.derivation == sai.derivation {
            Ok(&self_dig == sai)
        } else {
            Ok(sai.verify_binding(&self.to_derivation_data()?))
        }
    }

    pub fn to_derivation_data(&self) -> Result<Vec<u8>, Error> {
        Ok(match self.data.get_event_data() {
            EventData::Icp(icp) => DummyInceptionEvent::dummy_inception_data(
                icp,
                &(&self.get_digest().derivation).into(),
                self.serialization_info.kind,
            )?
            .derivation_data(
                &(&self.get_digest().derivation).into(),
                &self.serialization_info.kind,
            ),
            EventData::Dip(dip) => DummyInceptionEvent::dummy_delegated_inception_data(
                dip,
                &(&self.get_digest().derivation).into(),
                self.serialization_info.kind,
            )?
            .derivation_data(
                &(&self.get_digest().derivation).into(),
                &self.serialization_info.kind,
            ),
            _ => self.derivation_data(
                &(&self.get_digest().derivation).into(),
                &self.serialization_info.kind,
            ),
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
        match (self.data.get_event_data(), &self.event_type) {
            (EventData::Icp(_), _) | (EventData::Dip(_), _) => {
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
            (EventData::Rot(ref rot), EventTypeTag::Rot)
            | (EventData::Drt(ref rot), EventTypeTag::Rot) => {
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
            (EventData::Rot(ref drt), EventTypeTag::Drt)
            | (EventData::Drt(ref drt), EventTypeTag::Drt) => {
                self.data.apply_to(state.clone()).and_then(|next_state| {
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
                })
            }
            (EventData::Ixn(ref inter), _) => {
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
            _ => Err(Error::SemanticError("Wrong type tag".to_string())),
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
