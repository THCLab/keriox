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
        sections::{
            seal::{EventSeal, Seal},
            KeyConfig,
        },
        EventMessage,
    },
    event_message::{
        key_event_message::KeyEvent,
        signature::Signature,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
            TimestampedSignedEventMessage,
        },
    },
    prefix::{IdentifierPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState},
};

pub struct EventValidator {
    db: Arc<SledEventDatabase>,
}

impl EventValidator {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        Self { db }
    }

    /// Compute State for Prefix
    ///
    /// Returns the current State associated with
    /// the given Prefix
    pub fn compute_state(&self, id: &IdentifierPrefix) -> Result<Option<IdentifierState>, Error> {
        if let Some(events) = self.db.get_kel_finalized_events(id) {
            // start with empty state
            let mut state = IdentifierState::default();
            // we sort here to get inception first
            let mut sorted_events = events.collect::<Vec<TimestampedSignedEventMessage>>();
            // TODO why identifier is in database if there are no events for it?
            if sorted_events.is_empty() {
                return Ok(None);
            };
            sorted_events.sort();
            for event in sorted_events {
                state = match state.clone().apply(&event.signed_event_message) {
                    Ok(s) => s,
                    // will happen when a recovery has overridden some part of the KEL,
                    Err(e) => match e {
                        // skip out of order and partially signed events
                        Error::EventOutOfOrderError | Error::NotEnoughSigsError => continue,
                        // stop processing here
                        _ => break,
                    },
                };
            }
            Ok(Some(state))
        } else {
            // no inception event, no state
            Ok(None)
        }
    }

    /// Get keys from Establishment Event
    ///
    /// Returns the current Key Config associated with
    /// the given Prefix at the establishment event
    /// represented by sn and Event Digest
    fn get_keys_at_event(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingPrefix,
    ) -> Result<Option<KeyConfig>, Error> {
        if let Ok(Some(event)) = self.get_event_at_sn(id, sn) {
            // if it's the event we're looking for
            if event
                .signed_event_message
                .event_message
                .check_digest(event_digest)?
            {
                // return the config or error if it's not an establishment event
                Ok(Some(
                    match event
                        .signed_event_message
                        .event_message
                        .event
                        .get_event_data()
                    {
                        EventData::Icp(icp) => icp.key_config,
                        EventData::Rot(rot) => rot.key_config,
                        EventData::Dip(dip) => dip.inception_data.key_config,
                        EventData::Drt(drt) => drt.key_config,
                        // the receipt has a binding but it's NOT an establishment event
                        _ => return Err(Error::SemanticError("Receipt binding incorrect".into())),
                    },
                ))
            } else {
                Err(Error::SemanticError("Event digests doesn't match".into()))
            }
        } else {
            Err(Error::EventOutOfOrderError)
        }
    }

    pub fn get_event_at_sn(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<TimestampedSignedEventMessage>, Error> {
        if let Some(mut events) = self.db.get_kel_finalized_events(id) {
            Ok(events.find(|event| event.signed_event_message.event_message.event.get_sn() == sn))
        } else {
            Ok(None)
        }
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
        if let Ok(Some(event)) = self.get_event_at_sn(&seal.prefix, seal.sn) {
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
                Seal::Event(es) => delegated_event.check_digest(&es.event_digest).unwrap(),
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
                    .compute_state(&signed_event.event_message.event.get_prefix())?
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

    /// Process Event
    ///
    /// Validates a Key Event against the latest state
    /// of the Identifier and applies it to update the state
    /// returns the updated state
    /// TODO improve checking and handling of errors!
    pub fn process_event(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<Option<IdentifierState>, Error> {
        // If delegated event, check its delegator seal.
        if let Some(seal) = self.get_delegator_seal(signed_event)? {
            self.validate_seal(seal, &signed_event.event_message)?;
        };

        self.apply_to_state(&signed_event.event_message)
            .and_then(|new_state| {
                // add event from the get go and clean it up on failure later

                // self.db.add_kel_finalized_event(signed_event.clone(), id)?;
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
                                .db
                                .get_escrow_nt_receipts(&new_state.prefix)
                                .map(|rcts| {
                                    rcts.filter(|rct| {
                                        rct.body.event.sn
                                            == signed_event.event_message.event.get_sn()
                                    })
                                    .map(|rct| rct.couplets)
                                    .flatten()
                                    .collect()
                                })
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
    /// TODO improve checking and handling of errors!
    pub fn process_validator_receipt(
        &self,
        vrc: &SignedTransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        if let Ok(Some(event)) = self.get_event_at_sn(&vrc.body.event.prefix, vrc.body.event.sn) {
            let kp = self.get_keys_at_event(
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
        self.compute_state(&vrc.body.event.prefix)
    }

    /// Process Witness Receipt
    ///
    /// Checks the receipt against the receipted event
    /// returns the state of the Identifier being receipted,
    /// which may have been updated by un-escrowing events
    /// TODO improve checking and handling of errors!
    pub fn process_witness_receipt(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<Option<IdentifierState>, Error> {
        // get event which is being receipted
        let id = &rct.body.event.prefix.to_owned();
        if let Ok(Some(event)) = self.get_event_at_sn(&rct.body.event.prefix, rct.body.event.sn) {
            let serialized_event = event.signed_event_message.serialize()?;
            let (_, mut errors): (Vec<_>, Vec<Result<bool, Error>>) = rct
                .clone()
                .couplets
                .into_iter()
                .map(|(witness, receipt)| witness.verify(&serialized_event, &receipt))
                .partition(Result::is_ok);
            if errors.is_empty() {
                Ok(())
            } else {
                // TODO
                let e = errors.pop().unwrap().unwrap_err();
                Err(e)
            }
        } else {
            // There's no receipted event id database so we can't verify signatures
            Err(Error::MissingEvent)
        }?;
        self.compute_state(id)
    }

    fn apply_to_state(&self, event: &EventMessage<KeyEvent>) -> Result<IdentifierState, Error> {
        // get state for id (TODO cache?)
        self.compute_state(&event.event.get_prefix())
            // get empty state if there is no state yet
            .map(|opt| opt.map_or_else(IdentifierState::default, |s| s))
            // process the event update
            .and_then(|state| event.apply_to(state))
    }

    pub fn verify(&self, data: &[u8], sig: &Signature) -> Result<(), Error> {
        match sig {
            Signature::Transferable(seal, sigs) => {
                let kp = self.get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)?;
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

    #[cfg(feature = "query")]
    fn bada_logic(&self, new_rpy: &SignedReply) -> Result<(), Error> {
        use crate::query::{reply::ReplyEvent, Route};
        let accepted_replys = self
            .db
            .get_accepted_replys(&new_rpy.reply.event.get_prefix());

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
                match accepted_replys.and_then(|mut o| {
                    o.find(|r: &SignedReply| {
                        r.reply.event.get_route() == Route::ReplyKsn(seal.prefix.clone())
                    })
                }) {
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
                match accepted_replys.and_then(|mut o| {
                    o.find(|r| {
                        r.reply.event.get_route()
                            == Route::ReplyKsn(IdentifierPrefix::Basic(bp.clone()))
                    })
                }) {
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
            // if let Err(Error::EventOutOfOrderError) = verification_result {
            //     self.escrow_reply(&rpy)?;
            //     return Err(Error::QueryError(QueryError::OutOfOrderEventError));
            // }
            // verification_result?;
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
            // if let Err(Error::QueryError(QueryError::OutOfOrderEventError)) = ksn_checking_result {
            //     self.escrow_reply(&rpy)?;
            // };
            // ksn_checking_result?;
            // self.db
            //     .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix())?;
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
            .db
            .get_accepted_replys(pref)
            .ok_or(Error::QueryError(QueryError::OutOfOrderEventError))?
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
            None => {
                // TODO should be ok, if there's no old ksn in db?
                // Ok(())
                Err(QueryError::OutOfOrderEventError.into())
            }
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
            .get_event_at_sn(&ksn_pre, ksn_sn)?
            .ok_or(Error::QueryError(QueryError::OutOfOrderEventError))?
            .signed_event_message
            .event_message;
        event_from_db
            .check_digest(&ksn.state.last_event_digest)?
            .then(|| ())
            .ok_or::<Error>(Error::IncorrectDigest)?;

        match self.check_timestamp_with_last_ksn(ksn.timestamp, &ksn_pre, aid) {
            Err(Error::QueryError(QueryError::OutOfOrderEventError)) => {
                // no previous accepted ksn from that aid in db
                Ok(())
            }
            e => e,
        }?;

        // check new ksn with actual database state for that prefix
        let state = self
            .compute_state(&ksn_pre)?
            .ok_or::<Error>(QueryError::OutOfOrderEventError.into())?;
        if state.sn < ksn_sn {
            Err(QueryError::OutOfOrderEventError.into())
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
    let delegator_icp_raw= br#"{"v":"KERI10JSON000120_","t":"icp","d":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"n":"E7FuL3Z_KBgt_QAwuZi1lUFNC69wvyHSxnMFUsKjZHss","bt":"0","b":[],"c":[],"a":[]}-AABAAJEloPu7b4z8v1455StEJ1b7dMIz-P0tKJ_GBBCxQA8JEg0gm8qbS4TWGiHikLoZ2GtLA58l9dzIa2x_otJhoDA"#;
    let parsed = signed_message(delegator_icp_raw).unwrap().1;
    let deserialized_icp = Message::try_from(parsed).unwrap();
    event_processor.process(deserialized_icp.clone())?.unwrap();
    let delegator_id = "Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8".parse()?;

    // Delegated inception event.
    let dip_raw = br#"{"v":"KERI10JSON000154_","t":"dip","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","kt":"1","k":["DuK1x8ydpucu3480Jpd1XBfjnCwb3dZ3x5b1CJmuUphA"],"n":"EWWkjZkZDXF74O2bOQ4H5hu4nXDlKg2m4CBEBkUxibiU","bt":"0","b":[],"c":[],"a":[],"di":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8"}-AABAA_zcT2-86Zll3FG-hwoQiVuFiT0X28Ft0t4fZGNFISgtZjH2DCrBGoceko604NDZ0QF0Z3bSgEkN_y0lBafD_Bw-GAB0AAAAAAAAAAAAAAAAAAAAAAQE1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc"#;
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
        let delegating_event_raw = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"E1_-icBrwC_HhxyFwsQLV6hZEbApOc_McGUjhLONpQuc","i":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","s":"1","p":"Et78eYkh8A3H9w6Q87EC5OcijiVEJT8KyNtEGdpPVWV8","a":[{"i":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI","s":"0","d":"Er4bHXd4piEtsQat1mquwsNZXItvuoj_auCUyICmwyXI"}]}-AABAA6h5mD5stIwO_rwV9apMuhHXjxrKp2ATa35u-H6DM2X-BKo5NkJ1khzBdHo-VLQ6Zw_yajj2Ul_WOL8pFSk_ZDg"#;
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
