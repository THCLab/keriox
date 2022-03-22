#[cfg(feature = "query")]
use crate::prefix::IdentifierPrefix;
#[cfg(feature = "query")]
use crate::query::{key_state_notice::KeyStateNotice, reply::SignedReply, QueryError};
#[cfg(feature = "query")]
use chrono::{DateTime, FixedOffset};
use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
        EventMessage,
    },
    event_message::{
        key_event_message::KeyEvent,
        signature::Signature,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    state::{EventSemantics, IdentifierState},
};

use super::event_storage::EventStorage;

pub struct EventValidator {
    event_storage: EventStorage,
}

impl EventValidator {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        Self {
            event_storage: EventStorage::new(db),
        }
    }

    /// Process Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    pub fn validate_event(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<IdentifierState>, Error> {
        // If delegated event, check its delegator seal.
        if let Some(seal) = self.get_delegator_seal(signed_event)? {
            self.validate_seal(seal, &signed_event.event_message)?;
        };

        self.apply_to_state(&signed_event.event_message)
            .and_then(|new_state| {
                // match on verification result
                new_state
                    .current
                    .verify(
                        &signed_event.event_message.serialize()?,
                        &signed_event.signatures,
                    )
                    .and_then(|result| {
                        if !result {
                            Err(Error::SignatureVerificationError)
                        } else {
                            // check if there are enough receipts and escrow
                            let receipts_couplets: Vec<_> = self
                                .event_storage
                                .get_nt_receipts_signatures(
                                    &new_state.prefix,
                                    signed_event.event_message.event.get_sn(),
                                )
                                .unwrap_or_default();
                            if new_state
                                .witness_config
                                .enough_receipts(&receipts_couplets)?
                            {
                                Ok(Some(new_state))
                            } else {
                                Err(Error::NotEnoughReceiptsError)
                            }
                        }
                    })
            })
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
        if let Ok(Some(event)) = self
            .event_storage
            .get_event_at_sn(&vrc.body.event.prefix, vrc.body.event.sn)
        {
            let kp = self.event_storage.get_keys_at_event(
                &vrc.validator_seal.prefix,
                vrc.validator_seal.sn,
                &vrc.validator_seal.event_digest,
            )?;
            if kp.is_some()
                && kp.unwrap().verify(
                    &event.signed_event_message.event_message.serialize()?,
                    &vrc.signatures,
                )?
            {
                Ok(())
            } else {
                Err(Error::SignatureVerificationError)
            }
        } else {
            Err(Error::MissingEvent)
        }?;
        self.event_storage.get_state(&vrc.body.event.prefix)
    }

    /// Process Witness Receipt
    ///
    /// Checks the receipt against the receipted event
    /// returns the state of the Identifier being receipted,
    /// which may have been updated by un-escrowing events
    pub fn validate_witness_receipt(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        // get event which is being receipted
        let id = &rct.body.event.prefix.to_owned();
        if let Ok(Some(event)) = self
            .event_storage
            .get_event_at_sn(&rct.body.event.prefix, rct.body.event.sn)
        {
            let serialized_event = event.signed_event_message.serialize()?;
            let signer_couplets = self.event_storage.get_receipt_couplets(rct)?;
            let (_, errors): (Vec<_>, Vec<Result<bool, Error>>) = signer_couplets
                .into_iter()
                .map(|(witness, signature)| witness.verify(&serialized_event, &signature))
                .partition(Result::is_ok);
            if errors.is_empty() {
                Ok(())
            } else {
                Err(Error::SignatureVerificationError)
            }
        } else {
            // There's no receipted event id database so we can't verify signatures
            Err(Error::MissingEvent)
        }?;
        self.event_storage.get_state(id)
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), Error> {
        match sig {
            Signature::Transferable(seal, sigs) => {
                let kp = self.event_storage.get_keys_at_event(
                    &seal.prefix,
                    seal.sn,
                    &seal.event_digest,
                )?;
                (kp.is_some() && kp.unwrap().verify(data, sigs)?)
                    .then(|| ())
                    .ok_or(Error::SignatureVerificationError)
            }
            Signature::NonTransferable(bp, sign) => bp
                .verify(data, sign)?
                .then(|| ())
                .ok_or(Error::SignatureVerificationError),
        }
    }

    fn apply_to_state(&self, event: &EventMessage<KeyEvent>) -> Result<IdentifierState, Error> {
        // get state for id (TODO cache?)
        self.event_storage
            .get_state(&event.event.get_prefix())
            // get empty state if there is no state yet
            .map(|opt| opt.map_or_else(IdentifierState::default, |s| s))
            // process the event update
            .and_then(|state| event.apply_to(state))
    }

    /// Validate delegating event seal.
    ///
    /// Validates binding between delegated and delegating events. The validation
    /// is based on delegating event seal and delegated event.
    fn validate_seal(
        &self,
        seal: EventSeal,
        delegated_event: &EventMessage<KeyEvent>,
    ) -> Result<(), Error> {
        // Check if event of seal's prefix and sn is in db.
        if let Ok(Some(event)) = self.event_storage.get_event_at_sn(&seal.prefix, seal.sn) {
            // Extract prior_digest and data field from delegating event.
            let data = match event
                .signed_event_message
                .event_message
                .event
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
                    .check_digest(&es.event_digest)
                    .unwrap_or(false),
                _ => false,
            }) {
                return Err(Error::SemanticError(
                    "Data field doesn't contain delegating event seal.".to_string(),
                ));
            };
        } else {
            return Err(Error::EventOutOfOrderError);
        }
        Ok(())
    }

    fn get_delegator_seal(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<EventSeal>, Error> {
        // If delegated event, check its delegator seal.
        Ok(match signed_event.event_message.event.get_event_data() {
            EventData::Dip(dip) => {
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::SemanticError("Missing source seal".into()))?;
                Some(EventSeal {
                    prefix: dip.delegator,
                    sn,
                    event_digest: dig,
                })
            }
            EventData::Drt(_drt) => {
                let delegator = self
                    .event_storage
                    .get_state(&signed_event.event_message.event.get_prefix())?
                    .ok_or_else(|| {
                        Error::SemanticError("Missing state of delegated identifier".into())
                    })?
                    .delegator
                    .ok_or_else(|| Error::SemanticError("Missing delegator".into()))?;
                let (sn, dig) = signed_event
                    .delegator_seal
                    .as_ref()
                    .map(|seal| (seal.sn, seal.digest.clone()))
                    .ok_or_else(|| Error::SemanticError("Missing source seal".into()))?;
                Some(EventSeal {
                    prefix: delegator,
                    sn,
                    event_digest: dig,
                })
            }
            _ => None,
        })
    }
}

impl EventValidator {
    #[cfg(feature = "query")]
    fn bada_logic(&self, new_rpy: &SignedReply) -> Result<(), Error> {
        use crate::query::reply::ReplyEvent;

        let reply_prefix = new_rpy.reply.event.get_prefix();
        // helper function for reply timestamps checking
        fn check_dts(new_rpy: &ReplyEvent, old_rpy: &ReplyEvent) -> Result<(), Error> {
            let new_dt = new_rpy.get_timestamp();
            let old_dt = old_rpy.get_timestamp();
            if new_dt >= old_dt {
                Ok(())
            } else {
                Err(QueryError::StaleRpy.into())
            }
        }
        match new_rpy.signature.clone() {
            Signature::Transferable(seal, _sigs) => {
                // A) If sn (sequence number) of last (if forked) Est evt that provides
                //  keys for signature(s) of new is greater than sn of last Est evt
                //  that provides keys for signature(s) of old.

                //  Or

                //  B) If sn of new equals sn of old And date-time-stamp of new is
                //     greater than old

                // get last reply for prefix with route with sender_prefix
                match self
                    .event_storage
                    .get_last_reply(&reply_prefix, &seal.prefix)
                {
                    Some(old_rpy) => {
                        // check sns
                        let new_sn = seal.sn.clone();
                        let old_sn: u64 =
                            if let Signature::Transferable(seal, _) = old_rpy.signature {
                                seal.sn
                            } else {
                                return Err(QueryError::Error(
                                    "Improper signature type. Should be transferable.".into(),
                                )
                                .into());
                            };
                        if old_sn < new_sn {
                            Ok(())
                        } else if old_sn == new_sn {
                            check_dts(&new_rpy.reply.event, &old_rpy.reply.event)
                        } else {
                            Err(QueryError::StaleRpy.into())
                        }
                    }
                    None => Err(QueryError::NoSavedReply.into()),
                }
            }
            Signature::NonTransferable(bp, _sig) => {
                //  If date-time-stamp of new is greater than old

                match self
                    .event_storage
                    .get_last_reply(&reply_prefix, &IdentifierPrefix::Basic(bp))
                {
                    Some(old_rpy) => check_dts(&new_rpy.reply.event, &old_rpy.reply.event),
                    None => Err(QueryError::NoSavedReply.into()),
                }
            }
        }
    }

    #[cfg(feature = "query")]
    pub fn process_signed_reply(
        &self,
        rpy: &SignedReply,
    ) -> Result<Option<IdentifierState>, Error> {
        use crate::query::Route;

        let route = rpy.reply.event.get_route();
        // check if signature was made by ksn creator
        if let Route::ReplyKsn(ref aid) = route {
            if &rpy.signature.get_signer() != aid {
                return Err(QueryError::Error("Wrong reply message signer".into()).into());
            };
            self.verify(&rpy.reply.serialize()?, &rpy.signature)?;
            rpy.reply.check_digest()?;
            let bada_result = self.bada_logic(&rpy);
            match bada_result {
                Err(Error::QueryError(QueryError::NoSavedReply)) => {
                    // no previous rpy event to compare
                    Ok(())
                }
                anything => anything,
            }?;
            // now unpack ksn and check its details
            let ksn = rpy.reply.event.get_reply_data();
            self.check_ksn(&ksn, aid)?;
            Ok(Some(rpy.reply.event.get_state()))
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
        use crate::query::Route;

        match self
            .event_storage
            .db
            .get_accepted_replys(pref)
            .ok_or(Error::EventOutOfOrderError)?
            .find(|sr: &SignedReply| sr.reply.event.get_route() == Route::ReplyKsn(aid.clone()))
        {
            Some(old_ksn) => {
                let old_dt = old_ksn.reply.event.get_timestamp();
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
        // check ksn digest
        let ksn_sn = ksn.state.sn;
        let ksn_pre = ksn.state.prefix.clone();
        let event_from_db = self
            .event_storage
            .get_event_at_sn(&ksn_pre, ksn_sn)?
            .ok_or(Error::EventOutOfOrderError)?
            .signed_event_message
            .event_message;
        event_from_db
            .check_digest(&ksn.state.last_event_digest)?
            .then(|| ())
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
            .get_state(&ksn_pre)?
            .ok_or::<Error>(Error::EventOutOfOrderError)?;
        if state.sn < ksn_sn {
            Err(Error::EventOutOfOrderError)
        } else if state.sn == ksn_sn {
            Ok(Some(state))
        } else {
            Err(QueryError::StaleKsn.into())
        }
    }
}

#[test]
fn test_validate_seal() -> Result<(), Error> {
    use crate::event_message::Digestible;
    use crate::event_parsing::message::signed_message;
    use crate::processor::{EventProcessor, Message};
    use std::{convert::TryFrom, fs, sync::Arc};
    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = EventProcessor::new(Arc::clone(&db));

    // Events and sigs are from keripy `test_delegation` test.
    // (keripy/tests/core/test_delegating.py:#test_delegation)

    // Process icp.
    let delegator_icp_raw= br#"{"v":"KERI10JSON00012b_","t":"icp","d":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nt":"1","n":["EOmBSdblll8qB4324PEmETrFN-DhElyZ0BcBH1q1qukw"],"bt":"0","b":[],"c":[],"a":[]}-AABAAotHSmS5LuCg2LXwlandbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3tjcc8ySvYcpiBg"#;
    let parsed = signed_message(delegator_icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();
    event_processor.process(deserialized_icp.clone())?;
    let delegator_id = "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"nt":"1","n":["Ej1L6zmDszZ8GmBdYGeUYmAwoT90h3Dt9kRAS90nRyqI"],"bt":"0","b":[],"c":[],"a":[],"di":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0"}-AABAAbb1dks4dZCRcibL74840WKKtk9wsdMLLlmNFkjb1s7hBfevCqpN8nkZaewQFZu5QWR-rbZtN-Y8DDQ8lh_1WDA-GAB0AAAAAAAAAAAAAAAAAAAAAAQE4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A"#;
    let parsed = signed_message(dip_raw).unwrap().1;
    let msg = Message::try_from(parsed).unwrap();
    if let Message::Event(dip) = msg {
        let delegated_event_digest = dip.event_message.event.get_digest();
        // Construct delegating seal.
        let seal = EventSeal {
            prefix: delegator_id,
            sn: 1,
            event_digest: delegated_event_digest,
        };

        // Try to validate seal before processing delegating event
        assert!(matches!(
            event_processor
                .validator
                .validate_seal(seal.clone(), &dip.event_message),
            Err(Error::EventOutOfOrderError)
        ));

        // Process delegating event.
        let delegating_event_raw = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E4ncGiiaG9wbKMHrACX9iPxb7fMSSeBSnngBNIRoZ2_A","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"1","p":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":[{"i":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A","s":"0","d":"ESVGDRnpHMCAESkvj2bxKGAmMloX6K6vxfcmBLTOCM0A"}]}-AABAARpc88hIeWV9Z2IvzDl7dRHP-g1-EOYZLiDKyjNZB9PDSeGcNTj_SUXgWIVNdssPL7ajYvglbvxRwIU8teoFHCA"#;
        let parsed = signed_message(delegating_event_raw).unwrap().1;
        let deserialized_ixn = Message::try_from(parsed).unwrap();
        event_processor.process(deserialized_ixn.clone())?;

        // Validate seal again.
        assert!(event_processor
            .validator
            .validate_seal(seal, &dip.event_message)
            .is_ok());
    };

    Ok(())
}
