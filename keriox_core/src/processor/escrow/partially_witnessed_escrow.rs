use crate::event_message::keri_version::KeriVersion;
use std::{sync::Arc, time::Duration};

use said::{version::format::SerializationFormats, SelfAddressingIdentifier};

use crate::{
    actor::prelude::EventStorage,
    database::{EscrowCreator, EscrowDatabase, EventDatabase, LogDatabase},
    error::Error,
    event::receipt::Receipt,
    event_message::{
        signature::{verified_witness_signatures, Nontransferable},
        signed_event_message::{SignedEventMessage, SignedNontransferableReceipt},
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::notification::{Notification, NotificationBus, Notifier},
};

/// Store partially witnessed events and nontransferable receipts of events that
/// wasn't accepted into kel yet.
pub struct PartiallyWitnessedEscrow<D: EventDatabase + EscrowCreator> {
    db: Arc<D>,
    log: Arc<D::LogDatabaseType>,
    pub(crate) escrowed_partially_witnessed: D::EscrowDatabaseType,
}

impl<D: EventDatabase + EscrowCreator + 'static> PartiallyWitnessedEscrow<D> {
    pub fn new(db: Arc<D>, log_db: Arc<D::LogDatabaseType>, _duration: Duration) -> Self {
        let escrow_db = db.create_escrow_db("partially_witnessed_escrow");
        Self {
            log: log_db,
            db,
            escrowed_partially_witnessed: escrow_db,
        }
    }

    /// Returns all escrowed partially witness events of given identifier.
    pub fn get_partially_witnessed_events<'a>(
        &'a self,
        id: &IdentifierPrefix,
    ) -> Result<impl Iterator<Item = SignedEventMessage> + 'a, Error> {
        self.escrowed_partially_witnessed
            .get_from_sn(id, 0)
            .map_err(|_| Error::DbError)
    }

    /// Returns escrowed partially witness events of given identifier, sn and
    /// digest.
    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedEventMessage>, Error> {
        if self
            .escrowed_partially_witnessed
            .contains(id, sn, event_digest)
            .map_err(|_| Error::DbError)?
        {
            Ok(self
                .log
                .get_signed_event(&event_digest)
                .map_err(|_| Error::DbError)?
                .map(|ev| ev.signed_event_message))
        } else {
            Ok(None)
        }
    }

    /// Returns escrowed witness receipts for the event identified by the
    /// identifier, serial number (sn), and digest.
    fn get_escrowed_receipts<'a>(
        &'a self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &'a SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable> + 'a>, Error> {
        if self
            .escrowed_partially_witnessed
            .contains(id, sn, digest)
            .map_err(|_| Error::DbError)?
        {
            self.log
                .get_nontrans_couplets(digest)
                .map_err(|_| Error::DbError)
        } else {
            Ok(None)
        }
    }

    /// Saves nontransferable receipt in escrow.
    fn escrow_receipt(
        &self,
        receipt: SignedNontransferableReceipt,
        bus: &NotificationBus,
    ) -> Result<(), Error> {
        if receipt.signatures.is_empty() {
            // ignore events with no signatures
            Ok(())
        } else {
            let id = &receipt.body.prefix;
            let sn = receipt.body.sn;
            let digest = &receipt.body.receipted_event_digest;
            self.log
                .log_receipt_with_new_transaction(&receipt)
                .map_err(|_| Error::DbError)?;
            self.escrowed_partially_witnessed
                .save_digest(id, sn, digest)
                .map_err(|_| Error::DbError)?;

            bus.notify(&Notification::ReceiptEscrowed)
        }
    }

    fn accept_receipts_for(&self, event: &SignedEventMessage) -> Result<(), Error> {
        self.escrowed_partially_witnessed
            .remove(&event.event_message);
        Ok(())
    }

    /// Checks an escrowed event with its escrowed receipts and
    /// `additional_receipt`, and returns `additional_receipt` with only the
    /// witness signatures that verify.
    pub fn validate_partially_witnessed(
        &self,
        receipted_event: &SignedEventMessage,
        additional_receipt: Option<SignedNontransferableReceipt>,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        let storage = EventStorage::new(self.db.clone());
        let id = receipted_event.event_message.data.get_prefix();
        let sn = receipted_event.event_message.data.get_sn();
        let digest = receipted_event.event_message.digest()?;
        let new_state = storage
            .get_state(&id)
            .unwrap_or_default()
            .apply(receipted_event)?;

        // Keep the signatures of the additional receipt that verify.
        let additional_receipt = match additional_receipt {
            Some(receipt) => {
                let signatures = verified_witness_signatures(
                    receipt.signatures,
                    &new_state.witness_config.witnesses,
                    &receipted_event.event_message.encode()?,
                );
                if signatures.is_empty() {
                    return Err(Error::ReceiptVerificationError);
                }
                Some(SignedNontransferableReceipt {
                    body: receipt.body,
                    signatures,
                })
            }
            None => None,
        };
        // Verify receipted event signatures.
        new_state
            .current
            .verify(
                &receipted_event.event_message.encode()?,
                &receipted_event.signatures,
            )?
            .then_some(())
            .ok_or(Error::SignatureVerificationError)?;

        // Check signatures of receipts in database. Can be wrong if receipt came before event
        if let Some(escrowed_receipts) = self.get_escrowed_receipts(&id, sn, &digest)? {
            self.validate_receipts(
                escrowed_receipts,
                receipted_event,
                &new_state.witness_config.witnesses,
            )?;
        }

        let (couplets, indexed) = match (
            self.get_escrowed_receipts(&id, sn, &digest)?,
            &additional_receipt,
        ) {
            (None, None) => (vec![], vec![]),
            (None, Some(rct)) => Self::extract_receipt(rct.signatures.clone()),
            (Some(receipts), None) => Self::extract_receipt(receipts),
            (Some(receipts), Some(rct)) => {
                Self::extract_receipt(receipts.chain(rct.signatures.clone()))
            }
        };

        new_state
            .witness_config
            .enough_receipts(couplets, indexed)?
            .then_some(())
            .ok_or(Error::NotEnoughReceiptsError)?;
        Ok(additional_receipt)
    }

    /// Verify escrowed receipts and drop their wrong signatures: a group
    /// with a signature that does not verify is replaced by the signatures
    /// of it that do.
    fn validate_receipts(
        &self,
        rcts: impl IntoIterator<Item = Nontransferable>,
        event: &SignedEventMessage,
        witnesses: &[BasicPrefix],
    ) -> Result<(), Error> {
        let serialized_event = event.event_message.encode()?;
        let (wrong, verified): (Vec<_>, Vec<_>) = rcts
            .into_iter()
            .map(|group| {
                let verified =
                    verified_witness_signatures([group.clone()], witnesses, &serialized_event);
                (group, verified)
            })
            .filter(|(group, verified)| verified.first() != Some(group))
            .unzip();
        if wrong.is_empty() {
            return Ok(());
        }
        let digest = event.event_message.digest()?;
        self.log
            .remove_nontrans_receipt_with_new_transaction(&digest, wrong)
            .map_err(|_| Error::DbError)?;
        let verified = verified.into_iter().flatten().collect::<Vec<_>>();
        if !verified.is_empty() {
            let receipt = Receipt::new(
                KeriVersion::of(&event.event_message.serialization_info),
                SerializationFormats::JSON,
                digest,
                event.event_message.data.get_prefix(),
                event.event_message.data.get_sn(),
            );
            self.log
                .log_receipt_with_new_transaction(&SignedNontransferableReceipt::new(
                    &receipt, verified,
                ))
                .map_err(|_| Error::DbError)?;
        }
        Ok(())
    }

    /// Helper function for splitting iterator of transferable into couplets and
    /// indexed signatures.
    fn extract_receipt<I: IntoIterator<Item = Nontransferable>>(
        nontrans: I,
    ) -> (Vec<(BasicPrefix, SelfSigningPrefix)>, Vec<IndexedSignature>) {
        nontrans.into_iter().fold(
            (vec![], vec![]),
            |(mut all_couplets, mut all_indexed), snr| {
                match snr {
                    Nontransferable::Indexed(indexed_sigs) => {
                        all_indexed.append(&mut indexed_sigs.clone())
                    }
                    Nontransferable::Couplet(couplets_sigs) => {
                        all_couplets.append(&mut couplets_sigs.clone())
                    }
                };
                (all_couplets, all_indexed)
            },
        )
    }
}

impl<D: EventDatabase + EscrowCreator + 'static> Notifier for PartiallyWitnessedEscrow<D> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::ReceiptOutOfOrder(ooo) => {
                // Receipted event wasn't accepted into kel yet, so check escrowed
                // partially witnessed events.
                let sn = ooo.body.sn;
                let id = ooo.body.prefix.clone();
                // look for receipted event in partially witnessed. If there's no event yet, escrow receipt.
                match self.get_event_by_sn_and_digest(sn, &id, &ooo.body.receipted_event_digest)? {
                    None => self.escrow_receipt(ooo.clone(), bus),
                    Some(receipted_event) => {
                        // verify receipt signature
                        match self
                            .validate_partially_witnessed(&receipted_event, Some(ooo.to_owned()))
                        {
                            Ok(verified) => {
                                let ooo = verified.unwrap_or_else(|| ooo.clone());
                                self.log
                                    .log_receipt_with_new_transaction(&ooo)
                                    .map_err(|_| Error::DbError)?;
                                // accept event and remove receipts
                                self.db
                                    .accept_to_kel(&receipted_event.event_message)
                                    .map_err(|_| Error::DbError)?;
                                // accept receipts and remove them from escrow
                                self.accept_receipts_for(&receipted_event)?;
                                let witness_receipts =
                                    receipted_event.witness_receipts.map(|evs| {
                                        evs.into_iter().chain(ooo.signatures.clone()).collect()
                                    });
                                let added = SignedEventMessage {
                                    event_message: receipted_event.event_message,
                                    signatures: receipted_event.signatures,
                                    witness_receipts,
                                    // Preserve the delegation source seal. A
                                    // delegated dip/drt that reaches full
                                    // witnessing only after its receipt arrives
                                    // here; dropping the seal would emit the
                                    // event downstream (and to witnesses) without
                                    // its SourceSealCouples group, so no verifier
                                    // could anchor the delegation. The sibling
                                    // "already witnessed" arm keeps it too.
                                    delegator_seal: receipted_event.delegator_seal,
                                };

                                bus.notify(&Notification::KeyEventAdded(added))?;
                            }
                            Err(
                                Error::SignatureVerificationError
                                | Error::AbandonedIdentifier(_)
                                | Error::NonTransferableIdentifier(_)
                                | Error::ConfigTraitViolation(_),
                            ) => {
                                // remove from escrow
                                self.escrowed_partially_witnessed
                                    .remove(&receipted_event.event_message);
                            }
                            Err(Error::ReceiptVerificationError) => {
                                // ignore receipt with wrong signature
                            }
                            // save receipt in escrow
                            Err(_e) => {
                                self.escrow_receipt(ooo.clone(), bus)?;
                            }
                        }
                        Ok(())
                    }
                }
            }
            Notification::PartiallyWitnessed(signed_event) => {
                // ignore events with no signatures
                if signed_event.signatures.is_empty() {
                    return Ok(());
                }
                match self.validate_partially_witnessed(signed_event, None) {
                    Ok(_) => {
                        self.log
                            .log_event_with_new_transaction(&signed_event)
                            .map_err(|_| Error::DbError)?;
                        // accept event and remove receipts
                        self.db
                            .accept_to_kel(&signed_event.event_message)
                            .map_err(|_| Error::DbError)?;
                        // accept receipts and remove them from escrow
                        self.accept_receipts_for(&signed_event)?;

                        bus.notify(&Notification::KeyEventAdded(signed_event.clone()))?;
                    }
                    Err(
                        Error::SignatureVerificationError
                        | Error::AbandonedIdentifier(_)
                        | Error::NonTransferableIdentifier(_)
                        | Error::ConfigTraitViolation(_),
                    ) => (),
                    Err(_) => {
                        self.escrowed_partially_witnessed
                            .insert(&signed_event)
                            .map_err(|_| Error::DbError)?;
                    }
                };
                Ok(())
            }
            _ => Err(Error::SemanticError("Wrong notification".into())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, sync::Arc, time::Duration};

    use crate::event_message::cesr_adapter::parse_cesr_stream;
    use said::SelfAddressingIdentifier;
    use tempfile::NamedTempFile;

    use crate::{
        actor::prelude::{BasicProcessor, EventStorage, Message},
        database::{redb::RedbDatabase, EscrowDatabase, EventDatabase, QueryParameters},
        error::Error,
        event_message::signed_event_message::Notice,
        prefix::IdentifierPrefix,
        processor::{
            escrow::partially_witnessed_escrow::PartiallyWitnessedEscrow,
            notification::JustNotification, Processor,
        },
    };

    #[test]
    pub fn test_not_fully_witnessed() -> Result<(), Error> {
        use tempfile::Builder;

        // Create test db and event processor.
        // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();

        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let log_db = redb.log_db.clone();
        let events_db = Arc::new(redb);
        let event_processor = BasicProcessor::new(events_db.clone(), None);
        let event_storage = EventStorage::new(Arc::clone(&events_db));

        // Register not fully witnessed escrow, to save and reprocess events
        let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
            events_db.clone(),
            log_db,
            Duration::from_secs(10),
        ));
        event_processor.register_observer(
            partially_witnessed_escrow.clone(),
            &[
                JustNotification::PartiallyWitnessed,
                JustNotification::ReceiptOutOfOrder,
            ],
        )?;

        // check if receipt was escrowed
        let id: IdentifierPrefix = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();

        let digest: SelfAddressingIdentifier = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();

        // process icp event without processing receipts.
        let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0","kt":"2","k":["DLQ_T1HC_zZU5b3NsYhCQUX0c9GwyZW7U8pzkKTcFSod","DMW_TkkFsaufVLI0bYWjT7U8zZ_FV7PEiRF3W8RVGfpQ","DJEBW__ddS11UGhY_gofa4_PUE6SGU9wHFfk43AYW1zs"],"nt":"2","n":["EMBt6FEXUuQ02zCXVQicX2W60mmNy8VLiKUlokSf75WZ","EDTF0ZjY5ANPsHIONhplNVDOUEo5aQY9TiDTT3lm0JN6","EKw8rv7Uiugd6r7Zydvg6vY8MOQTOZtP43FodCH88hxk"],"bt":"2","b":["BN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev","BHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui","BJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb"],"c":[],"a":[]}-KADAABkmPJEhi5Pr8f-F4FEiBxU-5DF_Ff1LcyyYaOimqlPxs13RJWABWHx_NLQQ8L5O-pGW_zQ7dOWLP098IPoNFcJABAt-w_ejAVim4DrnqFQtZTwtoOqJrsvA1SWRvO-wu_FdyZDtcGhucP4Rl01irWx8MZlrCuY9QnftssqYcBTWBYOACAKMyHHcQ3htd4_NZwzBAUGgc0SxDdzeDvVeZa4g3iVfK4w0BMAOav2ebH8rcW6WoxsQcNyDHjkfYNTM4KNv50I"#;
        let parsed_icp = parse_cesr_stream(icp_raw).unwrap();
        let icp_msg = Message::try_from(parsed_icp).unwrap();
        event_processor.process(&icp_msg.clone())?;

        let state = event_storage.get_state(&id);
        assert_eq!(state, None);

        // check if icp is in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get_from_sn(&id, 0)
            .unwrap();
        if let Message::Notice(Notice::Event(ref ev)) = icp_msg {
            assert_eq!(
                ev.event_message.digest().unwrap(),
                esc.next().unwrap().event_message.digest().unwrap()
            );
        } else {
            panic!("Expected Event, got {:?}", icp_msg);
        }
        assert!(esc.next().is_none());

        let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
        let parsed_rcp = parse_cesr_stream(receipt0_0).unwrap();
        let rcp_msg = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg.clone())?;

        // check if icp still in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get_from_sn(&id, 0)
            .unwrap();
        if let Message::Notice(Notice::Event(ref ev)) = icp_msg {
            assert_eq!(
                ev.event_message.digest().unwrap(),
                esc.next().unwrap().event_message.digest().unwrap()
            );
        } else {
            panic!("Expected Event, got {:?}", icp_msg);
        }
        assert!(esc.next().is_none());

        // Check if receipt was saved in escrow
        let esc = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(esc.count(), 1);

        let state = event_storage.get_state(&id);
        assert_eq!(state, None);

        let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;
        let parsed_rcp = parse_cesr_stream(receipt0_1).unwrap();
        let rcp_msg = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg.clone())?;

        // check if icp still in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get_from_sn(&id, 0)
            .unwrap();
        assert!(esc.next().is_none());

        // Receipts should be removed from escrow, because threshold was met
        let esc = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap();
        assert!(esc.is_none());

        // check if receipt was accepted
        let mut esc = events_db
            .get_receipts_nt(QueryParameters::BySn {
                id: id.clone(),
                sn: 0,
            })
            .unwrap();

        let receipt = esc.next().unwrap();
        assert_eq!(receipt.signatures.len(), 2);

        let state = event_storage.get_state(&id).unwrap();
        assert_eq!(state.sn, 0);

        let receipt0_2 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb0BB8xozEus4sX8Tb6Ci0DB5jkuGN8MUfa0CidhIoCrqdBbopUeE6J3ynuDqLMB4V3MG9wlD6t2H2_o0rdVpK8GkM"#;
        let parsed_rcp = parse_cesr_stream(receipt0_2).unwrap();
        let rcp_msg = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg.clone())?;

        // check if receipt was escrowed, shouldn't be.
        let esc = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap();
        assert!(esc.is_none());

        let mut esc = events_db
            .get_receipts_nt(QueryParameters::BySn { id, sn: 0 })
            .unwrap();
        let receipt = esc.next().unwrap();
        assert_eq!(receipt.signatures.len(), 3);

        Ok(())
    }

    #[test]
    pub fn test_escrow_receipt_with_wrong_signature() -> Result<(), Error> {
        use tempfile::Builder;

        // Create test db and event processor.
        // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();

        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let log_db = redb.log_db.clone();
        let events_db = Arc::new(redb);
        let event_processor = BasicProcessor::new(events_db.clone(), None);
        let event_storage = EventStorage::new(Arc::clone(&events_db));

        // Register not fully witnessed escrow, to save and reprocess events
        let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
            events_db.clone(),
            log_db,
            Duration::from_secs(10),
        ));
        event_processor.register_observer(
            partially_witnessed_escrow.clone(),
            &[
                JustNotification::PartiallyWitnessed,
                JustNotification::ReceiptOutOfOrder,
            ],
        )?;

        // check if receipt was escrowed
        let id: IdentifierPrefix = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();
        let digest: SelfAddressingIdentifier = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();

        // process icp event without processing receipts.
        let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0","kt":"2","k":["DLQ_T1HC_zZU5b3NsYhCQUX0c9GwyZW7U8pzkKTcFSod","DMW_TkkFsaufVLI0bYWjT7U8zZ_FV7PEiRF3W8RVGfpQ","DJEBW__ddS11UGhY_gofa4_PUE6SGU9wHFfk43AYW1zs"],"nt":"2","n":["EMBt6FEXUuQ02zCXVQicX2W60mmNy8VLiKUlokSf75WZ","EDTF0ZjY5ANPsHIONhplNVDOUEo5aQY9TiDTT3lm0JN6","EKw8rv7Uiugd6r7Zydvg6vY8MOQTOZtP43FodCH88hxk"],"bt":"2","b":["BN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev","BHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui","BJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb"],"c":[],"a":[]}-KADAABkmPJEhi5Pr8f-F4FEiBxU-5DF_Ff1LcyyYaOimqlPxs13RJWABWHx_NLQQ8L5O-pGW_zQ7dOWLP098IPoNFcJABAt-w_ejAVim4DrnqFQtZTwtoOqJrsvA1SWRvO-wu_FdyZDtcGhucP4Rl01irWx8MZlrCuY9QnftssqYcBTWBYOACAKMyHHcQ3htd4_NZwzBAUGgc0SxDdzeDvVeZa4g3iVfK4w0BMAOav2ebH8rcW6WoxsQcNyDHjkfYNTM4KNv50I"#;
        let parsed_icp = parse_cesr_stream(icp_raw).unwrap();
        let icp_msg = Message::try_from(parsed_icp).unwrap();
        event_processor.process(&icp_msg.clone())?;

        let state = event_storage.get_state(&id);
        assert_eq!(state, None);

        // check if icp is in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get(&id, 0)
            .unwrap();
        if let Message::Notice(Notice::Event(ref ev)) = icp_msg {
            assert_eq!(
                ev.event_message.digest().unwrap(),
                esc.next().unwrap().event_message.digest().unwrap()
            );
        } else {
            panic!("Icp should be in escrow");
        }
        assert!(esc.next().is_none());

        // receipt with ok signature
        let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
        let parsed_rcp = parse_cesr_stream(receipt0_0).unwrap();
        let rcp_msg_0 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_0.clone())?;

        // check if icp is in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get(&id, 0)
            .unwrap();
        if let Message::Notice(Notice::Event(ref ev)) = icp_msg {
            assert_eq!(
                ev.event_message.digest().unwrap(),
                esc.next().unwrap().event_message.digest().unwrap()
            );
        } else {
            panic!("Icp should be in escrow");
        }
        assert!(esc.next().is_none());

        // Check if receipt was escrowed
        let mut escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        match rcp_msg_0 {
            Message::Notice(Notice::NontransferableRct(ref rct)) => {
                let nontrans_receipts = rct.signatures[0].clone();
                let escrowed_receipts_from_escrow = escrowed_receipts.next().unwrap();
                assert!(escrowed_receipts.next().is_none());
                assert_eq!(nontrans_receipts, escrowed_receipts_from_escrow);
            }
            _ => panic!("Expected NontransferableRct, got {:?}", rcp_msg_0),
        }

        // Check if event was accepted
        let state = event_storage.get_state(&id);
        assert_eq!(state, None);

        // receipt with wrong signature
        let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAG"#;
        let parsed_rcp = parse_cesr_stream(receipt0_1).unwrap();
        let rcp_msg_1 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_1.clone())?;

        // check if icp is in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get(&id, 0)
            .unwrap();
        if let Message::Notice(Notice::Event(ref ev)) = icp_msg {
            assert_eq!(
                ev.event_message.digest().unwrap(),
                esc.next().unwrap().event_message.digest().unwrap()
            );
        } else {
            panic!("Expected Event, got {:?}", icp_msg);
        }
        assert!(esc.next().is_none());

        // Check if receipt was escrowed. Shouldn't be because of wrong signature
        let escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(escrowed_receipts.count(), 1);

        // Check if event was accepted to KEL
        let esc = events_db.get_kel_finalized_events(QueryParameters::BySn {
            id: id.clone(),
            sn: 0,
        });
        assert!(esc.unwrap().next().is_none());

        let state = event_storage.get_state(&id);
        assert_eq!(state, None);

        Ok(())
    }

    #[test]
    pub fn test_out_of_order_receipt() -> Result<(), Error> {
        use tempfile::Builder;

        // Create test db and event processor.
        // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();

        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let log_db = redb.log_db.clone();
        let events_db = Arc::new(redb);
        let event_processor = BasicProcessor::new(events_db.clone(), None);
        let event_storage = EventStorage::new(Arc::clone(&events_db));

        // Register not fully witnessed escrow, to save and reprocess events
        let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
            events_db.clone(),
            log_db,
            Duration::from_secs(10),
        ));
        event_processor.register_observer(
            partially_witnessed_escrow.clone(),
            &[
                JustNotification::PartiallyWitnessed,
                JustNotification::ReceiptOutOfOrder,
            ],
        )?;

        // check if receipt was escrowed
        let id: IdentifierPrefix = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();
        let digest: SelfAddressingIdentifier = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();

        // first receipt
        let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
        let parsed_rcp = parse_cesr_stream(receipt0_0).unwrap();
        let rcp_msg_0 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_0.clone())?;

        // Check if receipt was escrowed
        let mut escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        match rcp_msg_0 {
            Message::Notice(Notice::NontransferableRct(ref rct)) => {
                let nontrans_receipts = rct.signatures[0].clone();
                let escrowed_receipts_from_escrow = escrowed_receipts.next().unwrap();
                assert!(escrowed_receipts.next().is_none());
                assert_eq!(nontrans_receipts, escrowed_receipts_from_escrow);
            }
            _ => panic!("Expected NontransferableRct, got {:?}", rcp_msg_0),
        }

        // second receipt
        let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;
        let parsed_rcp = parse_cesr_stream(receipt0_1).unwrap();
        let rcp_msg_1 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_1.clone())?;

        // Check if receipt was escrowed.
        let escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(escrowed_receipts.count(), 2);

        // process icp event
        let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0","kt":"2","k":["DLQ_T1HC_zZU5b3NsYhCQUX0c9GwyZW7U8pzkKTcFSod","DMW_TkkFsaufVLI0bYWjT7U8zZ_FV7PEiRF3W8RVGfpQ","DJEBW__ddS11UGhY_gofa4_PUE6SGU9wHFfk43AYW1zs"],"nt":"2","n":["EMBt6FEXUuQ02zCXVQicX2W60mmNy8VLiKUlokSf75WZ","EDTF0ZjY5ANPsHIONhplNVDOUEo5aQY9TiDTT3lm0JN6","EKw8rv7Uiugd6r7Zydvg6vY8MOQTOZtP43FodCH88hxk"],"bt":"2","b":["BN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev","BHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui","BJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb"],"c":[],"a":[]}-KADAABkmPJEhi5Pr8f-F4FEiBxU-5DF_Ff1LcyyYaOimqlPxs13RJWABWHx_NLQQ8L5O-pGW_zQ7dOWLP098IPoNFcJABAt-w_ejAVim4DrnqFQtZTwtoOqJrsvA1SWRvO-wu_FdyZDtcGhucP4Rl01irWx8MZlrCuY9QnftssqYcBTWBYOACAKMyHHcQ3htd4_NZwzBAUGgc0SxDdzeDvVeZa4g3iVfK4w0BMAOav2ebH8rcW6WoxsQcNyDHjkfYNTM4KNv50I"#;
        let parsed_icp = parse_cesr_stream(icp_raw).unwrap();
        let icp_msg = Message::try_from(parsed_icp).unwrap();
        event_processor.process(&icp_msg.clone())?;

        let state = event_storage.get_state(&id);
        assert!(state.is_some());

        // check if icp is in escrow
        let mut esc = partially_witnessed_escrow
            .escrowed_partially_witnessed
            .get(&id, 0)
            .unwrap();
        assert!(esc.next().is_none());

        // check if receipt escrow is empty
        let esc = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap();
        assert!(esc.is_none());

        // check if receipt was accepted
        let esc = events_db.get_receipts_nt(QueryParameters::BySn {
            id: id.clone(),
            sn: 0,
        });
        assert_eq!(esc.unwrap().next().unwrap().signatures.len(), 2);

        Ok(())
    }

    #[test]
    pub fn test_out_of_order_receipt_with_wrong_sig() -> Result<(), Error> {
        use tempfile::Builder;

        // Create test db and event processor.
        // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();

        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let log_db = redb.log_db.clone();
        let events_db = Arc::new(redb);
        let event_processor = BasicProcessor::new(events_db.clone(), None);
        let event_storage = EventStorage::new(Arc::clone(&events_db));

        // Register not fully witnessed escrow, to save and reprocess events
        let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
            events_db.clone(),
            log_db,
            Duration::from_secs(10),
        ));
        event_processor.register_observer(
            partially_witnessed_escrow.clone(),
            &[
                JustNotification::PartiallyWitnessed,
                JustNotification::ReceiptOutOfOrder,
            ],
        )?;

        // check if receipt was escrowed
        let id: IdentifierPrefix = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();
        let digest: SelfAddressingIdentifier = "EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9"
            .parse()
            .unwrap();

        // first receipt
        let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
        let parsed_rcp = parse_cesr_stream(receipt0_0).unwrap();
        let rcp_msg_0 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_0.clone())?;

        // Check if receipt was escrowed
        let mut escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        match rcp_msg_0 {
            Message::Notice(Notice::NontransferableRct(ref rct)) => {
                let nontrans_receipts = rct.signatures[0].clone();
                let escrowed_receipts_from_escrow = escrowed_receipts.next().unwrap();
                assert!(escrowed_receipts.next().is_none());
                assert_eq!(nontrans_receipts, escrowed_receipts_from_escrow);
            }
            _ => panic!("Expected NontransferableRct, got {:?}", rcp_msg_0),
        }

        // second receipt, wrong signature
        let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-MABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAF"#;
        let parsed_rcp = parse_cesr_stream(receipt0_1).unwrap();
        let rcp_msg_1 = Message::try_from(parsed_rcp).unwrap();
        event_processor.process(&rcp_msg_1.clone())?;

        // Check if receipt was escrowed.
        let escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(escrowed_receipts.count(), 2);

        // process icp event
        let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0","kt":"2","k":["DLQ_T1HC_zZU5b3NsYhCQUX0c9GwyZW7U8pzkKTcFSod","DMW_TkkFsaufVLI0bYWjT7U8zZ_FV7PEiRF3W8RVGfpQ","DJEBW__ddS11UGhY_gofa4_PUE6SGU9wHFfk43AYW1zs"],"nt":"2","n":["EMBt6FEXUuQ02zCXVQicX2W60mmNy8VLiKUlokSf75WZ","EDTF0ZjY5ANPsHIONhplNVDOUEo5aQY9TiDTT3lm0JN6","EKw8rv7Uiugd6r7Zydvg6vY8MOQTOZtP43FodCH88hxk"],"bt":"2","b":["BN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev","BHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui","BJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb"],"c":[],"a":[]}-KADAABkmPJEhi5Pr8f-F4FEiBxU-5DF_Ff1LcyyYaOimqlPxs13RJWABWHx_NLQQ8L5O-pGW_zQ7dOWLP098IPoNFcJABAt-w_ejAVim4DrnqFQtZTwtoOqJrsvA1SWRvO-wu_FdyZDtcGhucP4Rl01irWx8MZlrCuY9QnftssqYcBTWBYOACAKMyHHcQ3htd4_NZwzBAUGgc0SxDdzeDvVeZa4g3iVfK4w0BMAOav2ebH8rcW6WoxsQcNyDHjkfYNTM4KNv50I"#;
        let parsed_icp = parse_cesr_stream(icp_raw).unwrap();
        let icp_msg = Message::try_from(parsed_icp).unwrap();
        event_processor.process(&icp_msg.clone())?;

        // Check if receipt with wrong signature was removed
        let escrowed_receipts = partially_witnessed_escrow
            .get_escrowed_receipts(&id, 0, &digest)
            .unwrap()
            .unwrap();
        assert_eq!(escrowed_receipts.count(), 1);

        // Event wasn't accepted because it's not fully witnessed
        let state = event_storage.get_state(&id);
        assert!(state.is_none());

        Ok(())
    }
}
