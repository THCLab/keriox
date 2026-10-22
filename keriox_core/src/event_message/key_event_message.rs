use said::{derivation::HashFunctionCode, sad::SAD, SelfAddressingIdentifier};

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

    /// Whether `sai` is a digest of this event's content. The event's own
    /// `d` field is not trusted: the digest is always recomputed.
    pub fn compare_digest(&self, sai: &SelfAddressingIdentifier) -> Result<bool, Error> {
        Ok(sai.verify_binding(&self.to_derivation_data()?))
    }

    /// Fails unless the event's `d` field is the digest of its content.
    pub fn check_said(&self) -> Result<(), Error> {
        self.compare_digest(&self.digest()?)?
            .then_some(())
            .ok_or(Error::IncorrectDigest)
    }

    /// The serialization the event's SAID is computed over: the event with
    /// `d`, and for a self-addressing inception also `i`, replaced by
    /// placeholders.
    pub fn to_derivation_data(&self) -> Result<Vec<u8>, Error> {
        let event_digest = self.digest()?;
        let hash_function_code: HashFunctionCode = event_digest.derivation.into();
        let self_addressing = matches!(self.data.prefix, IdentifierPrefix::SelfAddressing(_));
        Ok(match self.data.get_event_data() {
            EventData::Icp(icp) if self_addressing => DummyInceptionEvent::dummy_inception_data(
                icp,
                &hash_function_code,
                self.serialization_info.clone(),
            )?
            .derivation_data()?,
            EventData::Dip(dip) if self_addressing => {
                DummyInceptionEvent::dummy_delegated_inception_data(
                    dip,
                    &hash_function_code,
                    self.serialization_info.clone(),
                )?
                .derivation_data()?
            }
            _ => self.derivation_data(&hash_function_code, &self.serialization_info.kind)?,
        })
    }
}

impl EventSemantics for KeriEvent<KeyEvent> {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let event_digest = self.digest()?;
        self.check_rotation_config()?;
        let mut state = self.apply_body_to(state)?;
        state.last_event_type = Some(self.event_type.clone());
        // The data of an establishment event only sees the prior event's
        // digest; its own is known here.
        if self.event_type.is_establishment_event() {
            state.last_est.digest = event_digest.into();
        }
        Ok(state)
    }
}

impl KeriEvent<KeyEvent> {
    /// The configuration traits field `c` of a rotation: REQUIRED in a KERI
    /// 2.0 body and absent from a KERI 1.0 one. Traits that may only appear
    /// in an inception are not allowed.
    fn check_rotation_config(&self) -> Result<(), Error> {
        let (EventData::Rot(rot) | EventData::Drt(rot)) = &self.data.event_data else {
            return Ok(());
        };
        match (self.serialization_info.major_version, &rot.config) {
            (2, None) => {
                return Err(Error::SemanticError(
                    "a KERI 2.0 rotation requires the configuration traits field c".into(),
                ))
            }
            (1, Some(_)) => {
                return Err(Error::SemanticError(
                    "a KERI 1.0 rotation has no configuration traits field c".into(),
                ))
            }
            _ => {}
        }
        match rot
            .config
            .iter()
            .flatten()
            .find(|t| ["EO", "DND", "DID"].contains(&t.as_str()))
        {
            Some(t) => Err(Error::ConfigTraitViolation(format!(
                "{t} may only appear in an inception"
            ))),
            None => Ok(()),
        }
    }

    fn apply_body_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        let event_digest = self.digest()?;
        self.check_said()?;
        let last_event_digest = &state.last_event_digest.said;
        // Update state.last with serialized current event message.
        match (self.data.get_event_data(), &self.event_type) {
            (EventData::Icp(_), _) | (EventData::Dip(_), _) => {
                if verify_identifier_binding(self)? {
                    self.data.apply_to(IdentifierState {
                        last_event_digest: event_digest.into(),
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
                        if last_event_digest.eq(rot.previous_event_hash()) {
                            Ok(IdentifierState {
                                last_event_digest: event_digest.into(),
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
                    if state.delegator.is_none() {
                        Err(Error::SemanticError(
                            "Applying delegated rotation to non-delegated state.".into(),
                        ))
                    } else if last_event_digest.eq(drt.previous_event_hash()) {
                        Ok(IdentifierState {
                            last_event_digest: event_digest.clone().into(),
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
                self.data.apply_to(state.clone()).and_then(|next_state| {
                    if last_event_digest.eq(inter.previous_event_hash()) {
                        Ok(IdentifierState {
                            last_event_digest: event_digest.into(),
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
                Ok(icp_event.compare_digest(&sap.said)? && icp_event.digest()?.eq(&sap.said))
            }
            IdentifierPrefix::SelfSigning(_ssp) => Ok(false),
        },
        EventData::Dip(_dip) => match &icp_event.data.get_prefix() {
            IdentifierPrefix::SelfAddressing(sap) => {
                Ok(icp_event.compare_digest(&sap.said)? && icp_event.digest()?.eq(&sap.said))
            }
            _ => Ok(false),
        },
        _ => Err(Error::SemanticError("Not an ICP or DIP event".into())),
    }
}
