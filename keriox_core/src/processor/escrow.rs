use std::{sync::Arc, time::Duration};

use super::{
    event_storage::EventStorage,
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
};
#[cfg(feature = "query")]
use crate::query::reply_event::ReplyRoute;
use crate::{
    database::{
        escrow::{Escrow, EscrowDb},
        SledEventDatabase,
    },
    error::Error,
    event::EventMessage,
    event_message::{
        key_event_message::KeyEvent,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
        Digestible,
    },
    prefix::{BasicPrefix, IdentifierPrefix, SelfAddressingPrefix, SelfSigningPrefix},
};

pub fn default_escrow_bus(
    event_db: Arc<SledEventDatabase>,
    escrow_db: Arc<EscrowDb>,
) -> (
    NotificationBus,
    (
        Arc<OutOfOrderEscrow>,
        Arc<PartiallySignedEscrow>,
        Arc<PartiallyWitnessedEscrow>,
    ),
) {
    let mut bus = NotificationBus::new();

    // Register out of order escrow, to save and reprocess out of order events
    let ooo_escrow = Arc::new(OutOfOrderEscrow::new(
        event_db.clone(),
        escrow_db.clone(),
        Duration::from_secs(10),
    ));
    bus.register_observer(
        ooo_escrow.clone(),
        vec![
            JustNotification::OutOfOrder,
            JustNotification::KeyEventAdded,
        ],
    );

    let ps_escrow = Arc::new(PartiallySignedEscrow::new(
        event_db.clone(),
        escrow_db.clone(),
        Duration::from_secs(10),
    ));
    bus.register_observer(ps_escrow.clone(), vec![JustNotification::PartiallySigned]);

    let pw_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        event_db.clone(),
        escrow_db.clone(),
        Duration::from_secs(10),
    ));
    bus.register_observer(
        pw_escrow.clone(),
        vec![
            JustNotification::PartiallyWitnessed,
            JustNotification::ReceiptOutOfOrder,
        ],
    );

    bus.register_observer(
        Arc::new(TransReceiptsEscrow::new(
            event_db.clone(),
            escrow_db.clone(),
            Duration::from_secs(10),
        )),
        vec![
            JustNotification::KeyEventAdded,
            JustNotification::TransReceiptOutOfOrder,
        ],
    );

    (bus, (ooo_escrow, ps_escrow, pw_escrow))
}

pub struct OutOfOrderEscrow {
    db: Arc<SledEventDatabase>,
    pub escrowed_out_of_order: Escrow<SignedEventMessage>,
}

impl OutOfOrderEscrow {
    pub fn new(db: Arc<SledEventDatabase>, escrow_db: Arc<EscrowDb>, duration: Duration) -> Self {
        let escrow = Escrow::new(b"ooes", duration, escrow_db);
        Self {
            db,
            escrowed_out_of_order: escrow,
        }
    }
}
impl Notifier for OutOfOrderEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let id = ev_message.event_message.event.get_prefix();
                self.process_out_of_order_events(bus, &id)?;
            }
            Notification::OutOfOrder(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    let id = match signed_event.event_message.event.get_event_data() {
                        crate::event::event_data::EventData::Dip(dip) => dip.delegator,
                        crate::event::event_data::EventData::Drt(_) => {
                            let id = signed_event.event_message.event.get_prefix();
                            if let Some(state) =
                                EventStorage::new(self.db.clone()).get_state(&id)?
                            {
                                match state.delegator {
                                    Some(id) => id,
                                    None => id,
                                }
                            } else {
                                id
                            }
                        }
                        _ => signed_event.event_message.event.get_prefix(),
                    };
                    self.escrowed_out_of_order.add(&id, signed_event.clone())?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

impl OutOfOrderEscrow {
    pub fn process_out_of_order_events(
        &self,
        bus: &NotificationBus,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_out_of_order.get(id) {
            for event in esc {
                let validator = EventValidator::new(self.db.clone());
                match validator.validate_event(&event) {
                    Ok(_) => {
                        // add to kel
                        self.db.add_kel_finalized_event(event.clone(), id)?;
                        // remove from escrow
                        self.escrowed_out_of_order.remove(id, &event)?;
                        bus.notify(&Notification::KeyEventAdded(event))?;
                        // stop processing the escrow if kel was updated. It needs to start again.
                        break;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.escrowed_out_of_order.remove(id, &event)?;
                    }
                    Err(_e) => (), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}

pub struct PartiallySignedEscrow {
    db: Arc<SledEventDatabase>,
    pub escrowed_partially_signed: Escrow<SignedEventMessage>,
}

impl PartiallySignedEscrow {
    pub fn new(db: Arc<SledEventDatabase>, escrow_db: Arc<EscrowDb>, duration: Duration) -> Self {
        let escrow = Escrow::new(b"pses", duration, escrow_db);
        Self {
            db,
            escrowed_partially_signed: escrow,
        }
    }

    pub fn get_partially_signed_for_event(
        &self,
        event: EventMessage<KeyEvent>,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        let id = event.event.get_prefix();
        self.escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(move |ev| ev.event_message == event))
    }

    fn remove_partially_signed(&self, event: &EventMessage<KeyEvent>) -> Result<(), Error> {
        let id = event.event.get_prefix();
        self.escrowed_partially_signed.get(&id).map(|events| {
            events
                .filter(|ev| &ev.event_message == event)
                .try_for_each(|ev| self.escrowed_partially_signed.remove(&id, &ev))
        });
        Ok(())
    }
}
impl Notifier for PartiallySignedEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::PartiallySigned(ev) => {
                if ev.signatures.is_empty() {
                    // ignore events with no signatures
                    Ok(())
                } else {
                    self.process_partially_signed_events(bus, ev)
                }
            }
            _ => Err(Error::SemanticError("Wrong notification".into())),
        }
    }
}

impl PartiallySignedEscrow {
    pub fn process_partially_signed_events(
        &self,
        bus: &NotificationBus,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Error> {
        let id = signed_event.event_message.event.get_prefix();
        if let Some(esc) = self
            .escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(|event| event.event_message == signed_event.event_message))
        {
            let new_sigs = esc
                .flat_map(|ev| ev.signatures)
                .chain(signed_event.signatures.clone().into_iter())
                .collect();

            let new_event = SignedEventMessage {
                signatures: new_sigs,
                ..signed_event.to_owned()
            };

            let validator = EventValidator::new(self.db.clone());
            match validator.validate_event(&new_event) {
                Ok(_) => {
                    // add to kel
                    self.db.add_kel_finalized_event(new_event.clone(), &id)?;
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::KeyEventAdded(new_event))?;
                }
                Err(_e) => {
                    //keep in escrow and save new partially signed event
                    self.escrowed_partially_signed
                        .add(&id, signed_event.clone())?;
                }
            }
        } else {
            self.escrowed_partially_signed
                .add(&id, signed_event.clone())?;
        };

        Ok(())
    }
}

/// Store partially witnessed events and nontransferable receipts of events that
/// wasn't accepted into kel yet.
pub struct PartiallyWitnessedEscrow {
    db: Arc<SledEventDatabase>,
    pub(crate) escrowed_partially_witnessed: Escrow<SignedEventMessage>,
    pub(crate) escrowed_nontranferable_receipts: Escrow<SignedNontransferableReceipt>,
}

impl PartiallyWitnessedEscrow {
    pub fn new(db: Arc<SledEventDatabase>, escrow_db: Arc<EscrowDb>, duration: Duration) -> Self {
        Self {
            db,
            escrowed_partially_witnessed: Escrow::new(b"pwes", duration, escrow_db.clone()),
            escrowed_nontranferable_receipts: Escrow::new(b"ures", duration, escrow_db.clone()),
        }
    }

    /// Return escrowed partially witness events of given identifier, sn and
    /// digest.
    fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Option<SignedEventMessage> {
        self.escrowed_partially_witnessed
            .get(id)
            .and_then(|mut events| {
                events.find(|event| {
                    event.event_message.event.content.sn == sn
                        && &event.event_message.event.content.prefix == id
                        && &event.event_message.get_digest() == event_digest
                })
            })
    }

    fn get_escrowed_receipts(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingPrefix,
    ) -> Option<Vec<SignedNontransferableReceipt>> {
        self.escrowed_nontranferable_receipts.get(&id).map(|r| {
            r.filter(|rct| rct.body.event.sn == sn && &rct.body.event.get_digest() == digest)
                // TODO avoid collect
                .collect()
        })
    }

    /// Saves nontransferable receipt in escrow.
    fn escrow_receipt(
        &self,
        receipt: SignedNontransferableReceipt,
        bus: &NotificationBus,
    ) -> Result<(), Error> {
        if receipt.couplets.is_none() && receipt.indexed_sigs.is_none() {
            // ignore events with no signatures
            Ok(())
        } else {
            let id = &receipt.body.event.prefix;
            self.escrowed_nontranferable_receipts
                .add(&id, receipt.clone())?;
            bus.notify(&Notification::ReceiptEscrowed)
        }
    }

    // Returns receipt couplets of event
    fn get_receipt_couplets(
        &self,
        rct: &SignedNontransferableReceipt,
        receipted_event: &SignedEventMessage,
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> {
        let couplets = rct.couplets.clone().unwrap_or_default();

        Ok(match &rct.indexed_sigs {
            Some(signatures) => {
                let storage = EventStorage::new(self.db.clone());
                let id = rct.body.event.prefix.clone();
                let new_state = storage.get_state(&id)?.unwrap_or_default().apply(receipted_event)?;

                let witnesses = new_state.witness_config.witnesses;
                let attached: Result<Vec<_>, Error> = signatures
                    .into_iter()
                    .map(|att| -> Result<_, _> {
                        Ok((
                            witnesses
                                .get(att.index as usize)
                                .ok_or_else(|| {
                                    Error::SemanticError("No matching witness prefix".into())
                                })?
                                .clone(),
                            att.signature.to_owned(),
                        ))
                    })
                    .collect();
                couplets.into_iter().chain(attached?.into_iter()).collect()
            }
            None => couplets,
        })
    }

    pub fn validate_receipt(
        &self,
        rct: &SignedNontransferableReceipt,
        receipted_event: &SignedEventMessage,
    ) -> Result<(), Error> {
        // verify receipts signatuers
        let serialized_event = receipted_event.event_message.serialize()?;
        let signer_couplets = self.get_receipt_couplets(rct, receipted_event)?;
        let failures: Result<(), Error> = signer_couplets
            .into_iter()
            .map(|(witness, signature)| {
                if witness.verify(&serialized_event, &signature).unwrap() {
                    Ok(())
                } else {
                    Err(Error::SemanticError("".into()))
                }
            })
            .collect();
        if !failures.is_err() {
            Ok(())
        } else {
            // remove from escrow if any signature is wrong
            self.escrowed_nontranferable_receipts
                .remove(&rct.body.event.prefix, rct)?;
            Err(Error::SignatureVerificationError)
        }
    }
}
impl Notifier for PartiallyWitnessedEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::ReceiptOutOfOrder(ooo) => {
                // Receipted event wasn't accepted into kel yet, so check escrowed
                // partailly witnessed events.
                let sn = ooo.body.event.sn;
                let id = ooo.body.event.prefix.clone();
                let digest = ooo.body.event.get_digest();
                // look for receipted event in partially witnessed. If there's no event yet, escrow receipt.
                match self.get_event_by_sn_and_digest(sn, &id, &ooo.body.get_digest()) {
                    None => self.escrow_receipt(ooo.clone(), bus),
                    Some(receipted_event) => {
                        // look for other receipts in escrowed receipts
                        let escrowed_receipts = self
                            .get_escrowed_receipts(&id, sn, &digest)
                            .unwrap_or_default()
                            .into_iter()
                            .chain([ooo.clone()]);

                        // Verify signatures of all receipts and remove those with wrong signatures
                        let (couplets, indexed) = escrowed_receipts
                            .clone()
                            .filter(|rct| self.validate_receipt(&rct, &receipted_event).is_ok())
                            .fold(
                                (vec![], vec![]),
                                |(mut all_couplets, mut all_indexed), snr| {
                                    if let Some(couplets) = snr.couplets {
                                        all_couplets.extend(couplets);
                                    };
                                    if let Some(indexed) = snr.indexed_sigs {
                                        all_indexed.extend(indexed);
                                    };
                                    (all_couplets, all_indexed)
                                },
                            );

                        let validator = EventValidator::new(self.db.clone());

                        let res =  validator.validate_event_with_receipts(
                            &receipted_event,
                            couplets,
                            indexed,
                        );

                        match res {
                            // accept event and remove receipts
                            Ok(Some(_)) => {
                                // add to kel
                                self.db
                                    .add_kel_finalized_event(receipted_event.clone(), &id)?;
                                // remove from escrow
                                self.escrowed_partially_witnessed
                                    .remove(&id, &receipted_event)?;
                                // accept receipts and remove them from escrow
                                escrowed_receipts.into_iter().for_each(|receipt| {
                                    self.escrowed_nontranferable_receipts
                                        .remove(&id, &receipt)
                                        .unwrap();
                                    self.db.add_receipt_nt(receipt.clone(), &id).unwrap();
                                });
                                bus.notify(&Notification::KeyEventAdded(receipted_event))?;
                            }
                            // Receipted event from unknown identifier. Escrow the receipt.
                            Ok(None) => {
                                self.escrow_receipt(ooo.clone(), bus)?;
                            }
                            Err(Error::SignatureVerificationError) => {
                                // remove from escrow
                                self.escrowed_partially_witnessed
                                    .remove(&id, &receipted_event)?;
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
                    let id = signed_event.event_message.event.get_prefix();
                    let sn = signed_event.event_message.event.get_sn();
                    let digest = signed_event.event_message.event.get_digest();
                    let receipt_couplets = self
                        .get_escrowed_receipts(&id, sn, &digest)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|rct| rct.couplets.unwrap())
                        .flatten();
                    let indexed_receipts = self
                        .get_escrowed_receipts(&id, sn, &digest)
                        .unwrap_or_default()
                        .into_iter()
                        .map(|rct| rct.indexed_sigs.unwrap())
                        .flatten();

                    // check if there's enough
                    let validator = EventValidator::new(self.db.clone());
                    match validator.validate_event_with_receipts(
                        signed_event,
                        receipt_couplets,
                        indexed_receipts,
                    ) {
                        Ok(Some(_)) => {
                            self.escrowed_partially_witnessed
                                .add(&id, signed_event.clone())?;
                        }
                        Err(Error::SignatureVerificationError) => (),
                        Err(_) | Ok(None) => {
                            self.escrowed_partially_witnessed
                                .add(&id, signed_event.clone())?;
                        }
                    };
                    Ok(())

                    // if yes, accept, otherwise save in parially witnessed escrow
                } else {
                    Ok(())
                }
            }
            _ => Err(Error::SemanticError("Wrong notification".into())),
            // _ => Ok(())
        }
    }
}

pub struct TransReceiptsEscrow {
    db: Arc<SledEventDatabase>,
    pub(crate) escrowed_trans_receipts: Escrow<SignedTransferableReceipt>,
}
impl TransReceiptsEscrow {
    pub fn new(db: Arc<SledEventDatabase>, escrow_db: Arc<EscrowDb>, duration: Duration) -> Self {
        Self {
            db,
            escrowed_trans_receipts: Escrow::new(b"vres", duration, escrow_db.clone()),
        }
    }
}
impl Notifier for TransReceiptsEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(event) => {
                self.process_t_receipts_escrow(&event.event_message.event.get_prefix(), bus)?;
            }
            Notification::TransReceiptOutOfOrder(receipt) => {
                // ignore events with no signatures
                if !receipt.signatures.is_empty() {
                    let id = receipt.validator_seal.prefix.clone();
                    self.escrowed_trans_receipts.add(&id, receipt.to_owned())?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }
        Ok(())
    }
}
impl TransReceiptsEscrow {
    pub fn process_t_receipts_escrow(
        &self,
        id: &IdentifierPrefix,
        bus: &NotificationBus,
    ) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_trans_receipts.get(id) {
            for timestamped_receipt in esc {
                let validator = EventValidator::new(self.db.clone());
                match validator.validate_validator_receipt(&timestamped_receipt) {
                    Ok(_) => {
                        // add to receipts
                        self.db.add_receipt_t(timestamped_receipt.clone(), &id)?;
                        // remove from escrow
                        self.escrowed_trans_receipts
                            .remove(&id, &timestamped_receipt)?;
                        bus.notify(&Notification::ReceiptAccepted)?;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.escrowed_trans_receipts
                            .remove(&id, &timestamped_receipt)?;
                    }
                    Err(e) => return Err(e), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}

#[cfg(feature = "query")]
#[derive(Clone)]
pub struct ReplyEscrow(Arc<SledEventDatabase>);
#[cfg(feature = "query")]
impl ReplyEscrow {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        Self(db)
    }
}
#[cfg(feature = "query")]
impl Notifier for ReplyEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KsnOutOfOrder(rpy) => {
                if let ReplyRoute::Ksn(id, _ksn) = rpy.reply.get_route() {
                    // let id = ksn.state.prefix;
                    self.0.add_escrowed_reply(rpy.clone(), &id)?;
                };
                Ok(())
            }
            &Notification::KeyEventAdded(_) => self.process_reply_escrow(bus),
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "query")]
impl ReplyEscrow {
    pub fn process_reply_escrow(&self, _bus: &NotificationBus) -> Result<(), Error> {
        use crate::query::QueryError;

        if let Some(esc) = self.0.get_all_escrowed_replys() {
            for sig_rep in esc {
                let validator = EventValidator::new(self.0.clone());
                let id = if let ReplyRoute::Ksn(_id, ksn) = sig_rep.reply.get_route() {
                    Ok(ksn.state.prefix)
                } else {
                    Err(Error::SemanticError("Wrong event type".into()))
                }?;
                match validator.process_signed_ksn_reply(&sig_rep) {
                    Ok(_) => {
                        self.0.remove_escrowed_reply(&id, &sig_rep)?;
                        self.0.update_accepted_reply(sig_rep, &id)?;
                    }
                    Err(Error::SignatureVerificationError)
                    | Err(Error::QueryError(QueryError::StaleRpy)) => {
                        // remove from escrow
                        self.0.remove_escrowed_reply(&id, &sig_rep)?;
                    }
                    Err(Error::EventOutOfOrderError) => (), // keep in escrow,
                    Err(e) => return Err(e),
                };
            }
        };
        Ok(())
    }
}
