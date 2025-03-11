use std::{sync::Arc, time::Duration};

use said::SelfAddressingIdentifier;

use crate::{
    actor::prelude::{EventStorage, SledEventDatabase},
    database::{
        escrow::{Escrow, EscrowDb},
        redb::{escrow_database::SnKeyDatabase, loging::LogDatabase, RedbDatabase, WriteTxnMode},
        EventDatabase,
    },
    error::Error,
    event::KeyEvent,
    event_message::{
        msg::TypedEvent,
        signature::Nontransferable,
        signed_event_message::{SignedEventMessage, SignedNontransferableReceipt},
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::notification::{Notification, NotificationBus, Notifier},
};

use super::maybe_out_of_order_escrow::SnKeyEscrow;

/// Store partially witnessed events and nontransferable receipts of events that
/// wasn't accepted into kel yet.
pub struct PartiallyWitnessedEscrow {
    db: Arc<RedbDatabase>,
    log: Arc<LogDatabase>,
    old_db: Arc<SledEventDatabase>,
    pub(crate) escrowed_partially_witnessed: SnKeyEscrow,
    // pub(crate) escrowed_partially_witnessed: Escrow<SignedEventMessage>,
    // pub(crate) escrowed_nontranferable_receipts: Escrow<SignedNontransferableReceipt>,
}

impl PartiallyWitnessedEscrow {
    pub fn new(
        db: Arc<RedbDatabase>,
        old_db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
    ) -> Self {
        let pwe_escrowdb = SnKeyEscrow::new(
            Arc::new(SnKeyDatabase::new(db.db.clone(), "partially_signed_escrow").unwrap()),
            db.log_db.clone(),
        );
        Self {
            log: db.log_db.clone(),
            db,
            old_db,
            escrowed_partially_witnessed: pwe_escrowdb,
            // escrowed_partially_witnessed: Escrow::new(b"pwes", duration, escrow_db.clone()),
            // escrowed_nontranferable_receipts: Escrow::new(b"ures", duration, escrow_db.clone()),
        }
    }

    /// Return escrowed partially witness events of given identifier, sn and
    /// digest.
    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingIdentifier,
    ) -> Option<SignedEventMessage> {
        let event = self.log.get_event(event_digest).unwrap();
        let witness_receipts = self
            .log
            .get_nontrans_couplets(event_digest)
            .unwrap()
            .map(|evs| evs.collect::<Vec<_>>());
        let signatures = self
            .log
            .get_signatures(event_digest)
            .unwrap()
            .map(|evs| evs.collect::<Vec<_>>());
        event.map(|event| SignedEventMessage {
            event_message: event,
            signatures: signatures.unwrap(),
            witness_receipts: witness_receipts,
            delegator_seal: None,
        })
    }

    fn get_escrowed_receipts(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Option<impl Iterator<Item = Nontransferable>> {
        self.log.get_nontrans_couplets(digest).unwrap()
        // self.escrowed_nontranferable_receipts.get(id).map(|r| {
        //     r.filter(|rct| rct.body.sn == sn && &rct.body.receipted_event_digest == digest)
        //         // TODO avoid collect
        //         .collect()
        // })
    }

    // pub fn get_partially_witnessed_events(&self) -> Vec<SignedEventMessage> {
    //     match self.escrowed_partially_witnessed.get_all() {
    //         Some(events) => events.collect(),
    //         None => vec![],
    //     }
    // }

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
            self.log.log_receipt(&WriteTxnMode::CreateNew, &receipt)?;
            self.escrowed_partially_witnessed
                .save_digest(id, sn, digest);

            bus.notify(&Notification::ReceiptEscrowed)
        }
    }

    fn accept_receipts_for(&self, event: &SignedEventMessage) -> Result<(), Error> {
        // let id = event.event_message.data.get_prefix();
        // let sn = event.event_message.data.sn;

        // self.db.accept_to_kel(&WriteTxnMode::CreateNew, &event.event_message)?;

        self.escrowed_partially_witnessed.remove(event);
        Ok(())
        // Ok(self
        //     .get_escrowed_receipts(
        //         &id,
        //         event.event_message.data.get_sn(),
        //         &event.event_message.digest()?,
        //     )
        //     .unwrap_or_default()
        //     .into_iter()
        //     .try_for_each(|receipt| {
        //         self.escrowed_nontranferable_receipts
        //             .remove(&id, &receipt)
        //             .unwrap();
        //         self.db.add_receipt_nt(receipt.clone(), &id)
        //     })
        //     .unwrap_or_default())
    }

    /// Returns receipt couplets of event
    fn get_receipt_couplets(
        rct: impl IntoIterator<Item = Nontransferable>,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> {
        let (mut indexed, mut couplets) = (vec![], vec![]);
        rct.into_iter().for_each(|signature| match signature {
            Nontransferable::Indexed(indexed_sigs) => indexed.append(&mut indexed_sigs.clone()),
            Nontransferable::Couplet(couplets_sigs) => couplets.append(&mut couplets_sigs.clone()),
        });

        let indexes: Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> = indexed
            .iter()
            .map(|inx| -> Result<_, _> {
                Ok((
                    witnesses
                        .get(inx.index.current() as usize)
                        .ok_or_else(|| Error::SemanticError("No matching witness prefix".into()))?
                        .clone(),
                    inx.signature.to_owned(),
                ))
            })
            .collect();

        Ok(couplets.into_iter().chain(indexes?).collect())
    }

    /// Verify escrowed receipts and remove those with wrong
    /// signatures.
    pub fn validate_receipt(
        &self,
        rcts: impl IntoIterator<Item = Nontransferable>,
        receipted_event: &TypedEvent<EventTypeTag, KeyEvent>,
        witnesses: &[BasicPrefix],
    ) -> Result<(), Error> {
        // verify receipts signatuers
        let serialized_event = receipted_event.encode()?;
        Self::get_receipt_couplets(rcts, witnesses)?
            .into_iter()
            .try_for_each(|(witness, signature)| {
                if witness.verify(&serialized_event, &signature)? {
                    Ok(())
                } else {
                    Err(Error::SignatureVerificationError)
                }
            })
        // .map_err(|e| {
        //     self.log.remove_receipt(&receipted_event.data.get_prefix(), receipted_event.data.get_sn(), &receipted_event.digest().unwrap());
        //     // remove from escrow if any signature is wrong
        //     match self
        //         .escrowed_nontranferable_receipts
        //         .remove(&rct.body.prefix, rct)
        //     {
        //         Ok(_) => e,
        //         Err(e) => e.into(),
        //     }
        // })
    }

    pub fn validate_partialy_witnessed(
        &self,
        receipted_event: &SignedEventMessage,
        additional_receipt: Option<SignedNontransferableReceipt>,
    ) -> Result<(), Error> {
        let storage = EventStorage::new(self.db.clone(), self.old_db.clone());
        let id = receipted_event.event_message.data.get_prefix();
        let sn = receipted_event.event_message.data.get_sn();
        let digest = receipted_event.event_message.digest()?;
        let new_state = storage
            .get_state(&id)
            .unwrap_or_default()
            .apply(receipted_event)?;

        // Verify additional receipt signature
        if let Some(ref receipt) = additional_receipt {
            let signatures = receipt.signatures.clone();
            let couplets = Self::get_receipt_couplets(
                signatures.into_iter(),
                &new_state.witness_config.witnesses,
            )?;
            couplets.iter().try_for_each(|(bp, sp)| {
                bp.verify(&receipted_event.event_message.encode()?, sp)?
                    .then_some(())
                    .ok_or(Error::ReceiptVerificationError)
            })?;
        }
        // Verify receipted event signatures.
        // TODO Do we need this here?
        new_state
            .current
            .verify(
                &receipted_event.event_message.encode()?,
                &receipted_event.signatures,
            )?
            .then_some(())
            .ok_or(Error::SignatureVerificationError)?;

        let (couplets, indexed) = if let Some(escrowed_nontrans) = self.get_escrowed_receipts(&id, sn, &digest) {
            let escrowed_non = escrowed_nontrans.collect::<Vec<_>>();
            self.validate_receipt(
                escrowed_non.clone(),
                &receipted_event.event_message,
                &new_state.witness_config.witnesses,
            )?;
            escrowed_non.into_iter()
            .chain(if let Some(rct) = additional_receipt {
                rct.signatures
            } else {
                Vec::default()
            })
            .fold(
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
            // Verify signatures of all receipts and remove those with wrong signatures
            // let (couplets, indexed) = self
            //     .get_escrowed_receipts(&id, sn, &digest)
            //     .unwrap()
            //     .filter(|rct| {
            //         let rr = self.validate_receipt(
            //             rct,
            //             &receipted_event.event_message,
            //             &new_state.witness_config.witnesses,
            //         );
            //         rr.is_ok()
            //     })
            // .chain(if let Some(rct) = additional_receipt {
            //     vec![rct]
            // } else {
            //     Vec::default()
            // })
            // .fold(
            //     (vec![], vec![]),
            //     |(mut all_couplets, mut all_indexed), snr| {
            //         snr.signatures.into_iter().for_each(|signature| {
            //             match signature {
            //                 Nontransferable::Indexed(indexed_sigs) => {
            //                     all_indexed.append(&mut indexed_sigs.clone())
            //                 }
            //                 Nontransferable::Couplet(couplets_sigs) => {
            //                     all_couplets.append(&mut couplets_sigs.clone())
            //                 }
            //             };
            //         });
            //         (all_couplets, all_indexed)
            //     },
            // );
            // check if there is enough of receipts
            
        } else {
            println!("\n\nNo receipts!!!!!!!!!!!");
            (vec![], vec![])
            
        };
        dbg!(&couplets);
        dbg!(&indexed);
        new_state
            .witness_config
            .enough_receipts(couplets, indexed)?
            .then_some(())
            .ok_or(Error::NotEnoughReceiptsError)?;
        println!("\n\nEnough receipts!!!!!!!!!!!");
        Ok(())
    }
}

impl Notifier for PartiallyWitnessedEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::ReceiptOutOfOrder(ooo) => {
                // Receipted event wasn't accepted into kel yet, so check escrowed
                // partailly witnessed events.
                let sn = ooo.body.sn;
                let id = ooo.body.prefix.clone();
                // look for receipted event in partially witnessed. If there's no event yet, escrow receipt.
                match self.get_event_by_sn_and_digest(sn, &id, &ooo.body.receipted_event_digest) {
                    None => self.escrow_receipt(ooo.clone(), bus),
                    Some(receipted_event) => {
                        // verify receipt signature
                        match self
                            .validate_partialy_witnessed(&receipted_event, Some(ooo.to_owned()))
                        {
                            Ok(_) => {
                                self.log.log_receipt(&WriteTxnMode::CreateNew, &ooo)?;
                                // accept event and remove receipts
                                self.db
                                    .accept_to_kel(
                                        &WriteTxnMode::CreateNew,
                                        &receipted_event.event_message,
                                    )
                                    .map_err(|_| Error::DbError)?;
                                // accept receipts and remove them from escrow
                                self.accept_receipts_for(&receipted_event)?;
                                let witness_receipts = receipted_event.witness_receipts.map(|evs| evs.into_iter().chain(ooo.signatures.clone()).collect());
                                let added = SignedEventMessage {
                                    event_message: receipted_event.event_message,
                                    signatures: receipted_event.signatures,
                                    witness_receipts,
                                    delegator_seal: None,
                                };
                                
                                bus.notify(&Notification::KeyEventAdded(added))?;
                            }
                            Err(Error::SignatureVerificationError) => {
                                // remove from escrow
                                self.escrowed_partially_witnessed.remove(&receipted_event);
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
                if !signed_event.signatures.is_empty() {
                    let id = signed_event.event_message.data.get_prefix();
                    match self.validate_partialy_witnessed(signed_event, None) {
                        Ok(_) => {
                            self.escrowed_partially_witnessed.insert(&signed_event)?;
                        }
                        Err(Error::SignatureVerificationError) => (),
                        Err(_) => {
                            self.escrowed_partially_witnessed.insert(&signed_event)?;
                        }
                    };
                    Ok(())
                } else {
                    Ok(())
                }
            }
            _ => Err(Error::SemanticError("Wrong notification".into())),
        }
    }
}
