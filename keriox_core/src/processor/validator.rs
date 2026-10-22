use std::sync::Arc;

#[cfg(feature = "query")]
use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::event_storage::EventStorage;
#[cfg(feature = "query")]
use crate::query::{key_state_notice::KeyStateNotice, reply_event::SignedReply, QueryError};
use crate::{
    database::EventDatabase,
    error::Error,
    event::{
        event_data::EventData,
        sections::{
            key_config::SignatureError,
            seal::{EventSeal, Seal},
        },
        KeyEvent,
    },
    event_message::{
        msg::KeriEvent,
        signature::{verified_witness_signatures, Nontransferable, Signature, SignerData},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::{IdentifierPrefix, IndexedSignature},
    state::{EventSemantics, IdentifierState},
};

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum VerificationError {
    #[error("Faulty signatures")]
    VerificationFailure,

    #[error(transparent)]
    SignatureError(#[from] SignatureError),

    #[error("Not establishment event: {0:?}")]
    NotEstablishment(EventSeal),

    #[error("Missing signer identifier")]
    MissingSignerId,

    #[error("Needs more info: {0}")]
    MoreInfo(#[from] MoreInfoError),
}

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum MoreInfoError {
    #[error("Corresponding event not found: {0}")]
    EventNotFound(EventSeal),
    #[error("Unknown signer identifier: {0}")]
    UnknownIdentifier(IdentifierPrefix),
}

pub struct EventValidator<D: EventDatabase> {
    event_storage: EventStorage<D>,
}

impl<D: EventDatabase> EventValidator<D> {
    pub fn new(event_database: Arc<D>) -> Self {
        Self {
            event_storage: EventStorage::new(event_database),
        }
    }
}
impl<D: EventDatabase> EventValidator<D> {
    /// Validate Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    pub fn validate_event(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<IdentifierState>, Error> {
        // The KERI specification: a key event without at least one
        // verifiable controller signature is dropped, not escrowed or
        // otherwise accepted, so spurious unsigned events cannot fill escrows.
        if signed_event.signatures.is_empty() {
            return Err(Error::MissingSignatures);
        }
        let id = signed_event.event_message.data.get_prefix();
        let new_state = match self
            .event_storage
            .get_state(&id)
            .map(|state| self.apply_signed(state, signed_event))
        {
            Some(Err(Error::EventDuplicateError)) => return Err(self.duplicate(signed_event)),
            Some(new_state) => new_state?,
            None => self.apply_signed(IdentifierState::default(), signed_event)?,
        };
        self.check_config_traits(signed_event)?;
        // If delegated event, check its delegator seal.
        if let Some(seal) = self.get_delegator_seal(signed_event)? {
            self.validate_seal(seal, &signed_event.event_message)?;
        };

        // check if there are enough receipts and escrow
        let sn = signed_event.event_message.data.get_sn();
        let (mut couples, mut indexed) = (vec![], vec![]);
        if let Some(rcts) = self.event_storage.get_nt_receipts(&id, sn)? {
            rcts.signatures.iter().for_each(|s| match s {
                Nontransferable::Couplet(c) => {
                    couples.append(&mut c.clone());
                }
                Nontransferable::Indexed(signatures) => indexed.append(&mut signatures.clone()),
            });
        };
        if new_state.witness_config.enough_receipts(couples, indexed)? {
            Ok(Some(new_state))
        } else {
            Err(Error::NotEnoughReceiptsError)
        }
    }

    /// The event's controller signatures that verify against the keys it is
    /// signed with: the keys it establishes, or the current ones for an
    /// interaction event.
    pub fn verified_signatures(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Vec<IndexedSignature>, Error> {
        let state = self
            .event_storage
            .get_state(&signed_event.event_message.data.get_prefix())
            .unwrap_or_default();
        Ok(signed_event
            .event_message
            .apply_to(state)?
            .current
            .verified_signatures(
                &signed_event.event_message.encode()?,
                &signed_event.signatures,
            ))
    }

    /// Applies the event to `state` and checks its controller signatures.
    /// Only the signatures that verify count: they must satisfy the new
    /// signing threshold and, for a rotation, the prior next threshold.
    fn apply_signed(
        &self,
        state: IdentifierState,
        signed_event: &SignedEventMessage,
    ) -> Result<IdentifierState, Error> {
        let new_state = signed_event.event_message.apply_to(state.clone())?;
        let verified = new_state.current.verified_signatures(
            &signed_event.event_message.encode()?,
            &signed_event.signatures,
        );
        if verified.is_empty() {
            return Err(Error::SignatureVerificationError);
        }
        if let EventData::Rot(rot) | EventData::Drt(rot) =
            signed_event.event_message.data.get_event_data()
        {
            state.current.next_keys_data.check_threshold(
                &rot.key_config.public_keys,
                verified.iter().map(|sig| &sig.index),
            )?;
        }
        new_state.current.threshold.enough_signatures(
            &verified
                .iter()
                .map(|sig| sig.index.current() as usize)
                .collect::<Vec<_>>(),
        )?;
        Ok(new_state)
    }

    /// Classifies an event at a location that already holds an accepted
    /// event. The KERI specification: a duplicitous event is a verified but
    /// different version of an event at the same location. The accepted
    /// event itself is not duplicitous, and an event that does not verify
    /// against the key state before its location is dropped.
    fn duplicate(&self, signed_event: &SignedEventMessage) -> Error {
        let id = signed_event.event_message.data.get_prefix();
        let sn = signed_event.event_message.data.get_sn();
        if let Some(accepted) = self.event_storage.get_event_at_sn(&id, sn) {
            if accepted.signed_event_message.event_message == signed_event.event_message {
                return Error::EventAlreadyAccepted;
            }
        }
        let prior = match sn.checked_sub(1) {
            None => Ok(Some(IdentifierState::default())),
            Some(prior_sn) => self.event_storage.compute_state_at_sn(&id, prior_sn),
        };
        match prior.map(|state| state.map(|state| self.apply_signed(state, signed_event))) {
            Ok(Some(Ok(_))) => Error::EventDuplicateError,
            Ok(Some(Err(Error::NotEnoughSigsError))) | Ok(None) => {
                Error::SignatureVerificationError
            }
            Ok(Some(Err(e))) | Err(e) => e,
        }
    }

    /// Process Validator Receipt
    ///
    /// Checks the receipt against the receipted event
    /// and the state of the validator, returns the state
    /// of the identifier being receipted
    pub fn validate_validator_receipt(
        &self,
        vrc: &SignedTransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        self.event_storage
            .refuse_abandoned_signer(Some(&vrc.validator_seal.prefix))?;
        if let Some(event) = self
            .event_storage
            .get_event_at_sn(&vrc.body.prefix, vrc.body.sn)
        {
            let kp = self
                .event_storage
                .get_keys_at_event(
                    &vrc.validator_seal.prefix,
                    vrc.validator_seal.sn,
                    &vrc.validator_seal.event_digest(),
                )?
                .ok_or(Error::EventOutOfOrderError)?;
            if kp.verify(
                &event.signed_event_message.event_message.encode()?,
                &vrc.signatures,
            )? {
                Ok(())
            } else {
                Err(Error::SignatureVerificationError)
            }
        } else {
            Err(Error::MissingEvent)
        }?;
        Ok(self.event_storage.get_state(&vrc.body.prefix))
    }

    /// Process Witness Receipt
    ///
    /// Checks the receipt against the receipted event and returns it with
    /// only the witness signatures that verify, or an error when none does.
    pub fn validate_witness_receipt(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<SignedNontransferableReceipt, Error> {
        let (id, sn) = (&rct.body.prefix, rct.body.sn);
        // There's no receipted event id database so we can't verify signatures
        let event = self
            .event_storage
            .get_event_at_sn(id, sn)
            .ok_or(Error::MissingEvent)?;
        let witnesses = self
            .event_storage
            .compute_state_at_event(sn, id, &rct.body.receipted_event_digest)?
            .ok_or(Error::MissingEvent)?
            .witness_config
            .witnesses;
        let signatures = verified_witness_signatures(
            rct.signatures.clone(),
            &witnesses,
            &event.signed_event_message.event_message.encode()?,
        );
        if signatures.is_empty() {
            return Err(Error::SignatureVerificationError);
        }
        Ok(SignedNontransferableReceipt {
            body: rct.body.clone(),
            signatures,
        })
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), VerificationError> {
        match sig {
            Signature::Transferable(signer_data, sigs) => {
                let seal = match signer_data {
                    SignerData::EventSeal(seal) => Ok(seal.clone()),
                    SignerData::LastEstablishment(id) => self
                        .event_storage
                        .get_last_establishment_event_seal(id)
                        .ok_or::<VerificationError>(
                            MoreInfoError::UnknownIdentifier(id.clone()).into(),
                        ),
                    SignerData::JustSignatures => Err(VerificationError::MissingSignerId),
                }?;
                let kp = self
                    .event_storage
                    .get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest())
                    .map_err(|_| VerificationError::NotEstablishment(seal.clone()))?; // error means that event wasn't found
                match kp {
                    Some(kp) => kp
                        .verify(data, sigs)?
                        .then_some(())
                        .ok_or(VerificationError::VerificationFailure),
                    None => Err(MoreInfoError::EventNotFound(seal).into()),
                }
            }
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => {
                crate::event_message::signature::couplets_verify(couplets, data)
                    .then_some(())
                    .ok_or(VerificationError::VerificationFailure)
            }
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                Err(VerificationError::MissingSignerId)
            }
        }
    }

    /// Validate delegating event seal.
    ///
    /// Validates binding between delegated and delegating events. The validation
    /// is based on delegating event seal and delegated event.
    fn validate_seal(
        &self,
        seal: EventSeal,
        delegated_event: &KeriEvent<KeyEvent>,
    ) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        let found = self.event_storage.get_event_at_sn(&seal.prefix, seal.sn);
        tracing::debug!(
            delegator = %seal.prefix,
            sn = seal.sn,
            seal_digest = %seal.event_digest(),
            found = found.is_some(),
            "validate_seal: looking up the delegating event"
        );
        if let Some(event) = found {
            // Extract prior_digest and data field from delegating event.
            let data = match event
                .signed_event_message
                .event_message
                .data
                .get_event_data()
            {
                EventData::Rot(rot) => rot.data,
                EventData::Ixn(ixn) => ixn.data,
                EventData::Drt(drt) => drt.data,
                _ => return Err(Error::SemanticError("Improper event type".to_string())),
            };

            // Check if event seal list contains delegating event seal.
            if !data.iter().any(|s| match s {
                Seal::Event(es) => delegated_event
                    .compare_digest(&es.event_digest())
                    .unwrap_or(false),
                _ => false,
            }) {
                return Err(Error::SemanticError(
                    "Data field doesn't contain delegating event seal.".to_string(),
                ));
            };
        } else {
            return Err(Error::MissingDelegatingEventError);
        }
        Ok(())
    }

    /// Drops an event that breaks a configuration trait of the inception of
    /// its own KEL (`EO`: establishment events only) or of its delegator's
    /// (`DND`: do not delegate), as the KERI specification requires. A trait
    /// of a KEL not known yet is checked once that KEL arrives, when the
    /// event is released from its escrow.
    fn check_config_traits(&self, signed_event: &SignedEventMessage) -> Result<(), Error> {
        let event = &signed_event.event_message;
        let id = event.data.get_prefix();
        if matches!(event.data.get_event_data(), EventData::Ixn(_))
            && self.inception_traits(&id).iter().any(|t| t == "EO")
        {
            return Err(Error::ConfigTraitViolation(format!(
                "{id} is establishment only (EO): no interaction events"
            )));
        }
        let delegator = match (event.data.get_event_data(), &event.event_type) {
            (EventData::Dip(dip), _) => Some(dip.delegator),
            (_, crate::event_message::EventTypeTag::Drt) => self
                .event_storage
                .get_state(&id)
                .and_then(|state| state.delegator),
            _ => None,
        };
        if let Some(delegator) = delegator {
            if self.inception_traits(&delegator).iter().any(|t| t == "DND") {
                return Err(Error::ConfigTraitViolation(format!(
                    "delegator {delegator} does not delegate (DND)"
                )));
            }
        }
        Ok(())
    }

    /// Configuration traits of the inception of `id`'s KEL, if known.
    fn inception_traits(&self, id: &IdentifierPrefix) -> Vec<String> {
        self.event_storage
            .get_event_at_sn(id, 0)
            .map(
                |icp| match icp.signed_event_message.event_message.data.event_data {
                    EventData::Icp(icp) => icp.inception_configuration,
                    EventData::Dip(dip) => dip.inception_data.inception_configuration,
                    _ => vec![],
                },
            )
            .unwrap_or_default()
    }

    fn get_delegator_seal(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<EventSeal>, Error> {
        // If delegated event, check its delegator seal. A parsed `drt`
        // carries the same data as a `rot`, so only the type tag tells a
        // delegated rotation apart.
        let event = &signed_event.event_message;
        Ok(match (event.data.get_event_data(), &event.event_type) {
            (EventData::Dip(dip), _) => {
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::MissingDelegatorSealError(dip.delegator.clone()))?;
                Some(EventSeal::new(dip.delegator, sn, dig.into()))
            }
            (EventData::Rot(_) | EventData::Drt(_), crate::event_message::EventTypeTag::Drt) => {
                let delegator = self
                    .event_storage
                    .get_state(&signed_event.event_message.data.get_prefix())
                    .ok_or_else(|| {
                        Error::SemanticError("Missing state of delegated identifier".into())
                    })?
                    .delegator
                    .ok_or_else(|| Error::SemanticError("Missing delegator".into()))?;
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::MissingDelegatorSealError(delegator.clone()))?;
                Some(EventSeal::new(delegator, sn, dig.into()))
            }
            _ => None,
        })
    }
}

impl<D: EventDatabase> EventValidator<D> {
    #[cfg(feature = "query")]
    pub fn process_signed_ksn_reply(
        &self,
        rpy: &SignedReply,
    ) -> Result<Option<IdentifierState>, Error> {
        use crate::query::reply_event::{bada_logic, ReplyRoute};

        let route = rpy.reply.get_route();
        // check if signature was made by ksn creator
        if let ReplyRoute::Ksn(signer_id, ksn) = route {
            if rpy.signature.get_signer().ok_or(Error::MissingSigner)? != signer_id {
                return Err(QueryError::Error("Wrong reply message signer".into()).into());
            };
            self.event_storage
                .refuse_abandoned_signer(Some(&signer_id))?;
            self.verify(&rpy.reply.encode()?, &rpy.signature)?;

            rpy.reply.check_digest()?;
            let reply_prefix = ksn.state.prefix.clone();

            // check if there's previous reply to compare
            if let Some(old_rpy) = self.event_storage.get_last_ksn_reply(
                &reply_prefix,
                &rpy.signature.get_signer().ok_or(Error::MissingSigner)?,
            ) {
                bada_logic(rpy, &old_rpy)?;
            };

            // now unpack ksn and check its details
            self.check_ksn(&ksn, &signer_id)?;
            Ok(Some(ksn.state))
        } else {
            Err(Error::SemanticError("wrong route type".into()))
        }
    }

    #[cfg(feature = "query")]
    pub fn check_timestamp_with_last_ksn(
        &self,
        new_dt: DateTime<FixedOffset>,
        pref: &IdentifierPrefix,
        aid: &IdentifierPrefix,
    ) -> Result<(), Error> {
        match self.event_storage.get_last_ksn_reply(pref, aid) {
            Some(old_ksn) => {
                let old_dt = old_ksn.reply.get_timestamp();
                if old_dt > new_dt {
                    Err(QueryError::StaleKsn.into())
                } else {
                    Ok(())
                }
            }
            None => Err(Error::EventOutOfOrderError),
        }
    }

    #[cfg(feature = "query")]
    fn check_ksn(
        &self,
        ksn: &KeyStateNotice,
        aid: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        use std::cmp::Ordering;

        // check ksn digest
        let ksn_sn = ksn.state.sn;
        let ksn_pre = ksn.state.prefix.clone();
        let event_from_db = self
            .event_storage
            .get_event_at_sn(&ksn_pre, ksn_sn)
            .ok_or(Error::EventOutOfOrderError)?
            .signed_event_message
            .event_message;
        event_from_db
            .compare_digest(&ksn.state.last_event_digest.clone().into())?
            .then_some(())
            .ok_or::<Error>(Error::IncorrectDigest)?;

        match self.check_timestamp_with_last_ksn(ksn.timestamp, &ksn_pre, aid) {
            Err(Error::EventOutOfOrderError) => {
                // no previous accepted ksn from that aid in db
                Ok(())
            }
            e => e,
        }?;

        // check new ksn with actual database state for that prefix
        let state = self
            .event_storage
            .get_state(&ksn_pre)
            .ok_or::<Error>(Error::EventOutOfOrderError)?;

        match state.sn.cmp(&ksn_sn) {
            Ordering::Less => Err(Error::EventOutOfOrderError),
            Ordering::Equal => Ok(Some(state)),
            Ordering::Greater => Err(QueryError::StaleKsn.into()),
        }
    }
}

#[test]
fn test_validate_seal() -> Result<(), Error> {
    use crate::event_message::cesr_adapter::parse_cesr_stream;
    use std::{convert::TryFrom, fs, sync::Arc};

    use tempfile::Builder;

    use crate::{
        database::redb::RedbDatabase,
        event_message::signed_event_message::{Message, Notice},
        processor::{basic_processor::BasicProcessor, Processor},
    };
    use tempfile::NamedTempFile;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let events_db_path = NamedTempFile::new().unwrap();
    let events_database = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let event_processor = BasicProcessor::new(events_database.clone(), None);

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py:#test_delegation)

    // Process icp.
    let delegator_icp_raw = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}-KABAAArkDBeflIAo4kBsKnc754XHJvdLnf04iq-noTFEJkbv2MeIGZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0-nlhHEE"#;
    let parsed = parse_cesr_stream(delegator_icp_raw).unwrap();
    let deserialized_icp = Message::try_from(parsed).unwrap();
    event_processor.process(&deserialized_icp)?;
    let delegator_id = "EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","kt":"1","k":["DLitcfMnabnLt-PNCaXdVwX45wsG93Wd8eW9QiZrlKYQ"],"nt":"1","n":["EDjXvWdaNJx7pAIr72Va6JhHxc7Pf4ScYJG496ky8lK8"],"bt":"0","b":[],"c":[],"a":[],"di":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH"}-KABAABv6Q3s-1Tif-ksrx7ul9OKyOL_ZPHHp6lB9He4n6kswjm9VvHXzWB3O7RS2OQNWhx8bd3ycg9bWRPRrcKADoYC-SAB0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS"#;
    let parsed = parse_cesr_stream(dip_raw).unwrap();
    let msg = Message::try_from(parsed).unwrap();
    if let Message::Notice(Notice::Event(dip)) = msg {
        let delegated_event_digest = dip.event_message.digest()?;
        // Construct delegating seal.
        let seal = EventSeal::new(delegator_id, 1, delegated_event_digest.into());

        let validator = EventValidator::new(events_database.clone());
        // Try to validate seal before processing delegating event
        assert!(matches!(
            validator.validate_seal(seal.clone(), &dip.event_message),
            Err(Error::MissingDelegatingEventError)
        ));

        // Process delegating event.
        let delegating_event_raw = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}-KABAADFmoctrQkBbm47vuk7ejMbQ1y5vKD0Nfo8cqzbETZAlEPdbgVRSFta1-Bpv0y1RiDrCxa_0IOp906gYqDPXIwG"#;
        let parsed = parse_cesr_stream(delegating_event_raw).unwrap();
        let deserialized_ixn = Message::try_from(parsed).unwrap();
        event_processor.process(&deserialized_ixn)?;

        // Validate seal again.
        assert!(validator.validate_seal(seal, &dip.event_message).is_ok());
    };

    Ok(())
}
