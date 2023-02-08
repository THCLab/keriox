use std::{sync::Arc, time::Duration};

use sai::{sad::SAD, SelfAddressingPrefix};

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
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal, SourceSeal},
        KeyEvent,
    },
    event_message::{
        msg::KeriEvent,
        signature::Nontransferable,
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
};

#[derive(Debug, Clone)]
pub struct EscrowConfig {
    pub out_of_order_timeout: Duration,
    pub partially_signed_timeout: Duration,
    pub partially_witnessed_timeout: Duration,
    pub trans_receipt_timeout: Duration,
    pub delegation_timeout: Duration,
}

impl Default for EscrowConfig {
    fn default() -> Self {
        Self {
            out_of_order_timeout: Duration::from_secs(60),
            partially_signed_timeout: Duration::from_secs(60),
            partially_witnessed_timeout: Duration::from_secs(60),
            trans_receipt_timeout: Duration::from_secs(60),
            delegation_timeout: Duration::from_secs(60),
        }
    }
}

pub fn default_escrow_bus(
    event_db: Arc<SledEventDatabase>,
    escrow_db: Arc<EscrowDb>,
    escrow_config: EscrowConfig,
) -> (
    NotificationBus,
    (
        Arc<OutOfOrderEscrow>,
        Arc<PartiallySignedEscrow>,
        Arc<PartiallyWitnessedEscrow>,
        Arc<DelegationEscrow>,
    ),
) {
    let mut bus = NotificationBus::new();

    // Register out of order escrow, to save and reprocess out of order events
    let ooo_escrow = Arc::new(OutOfOrderEscrow::new(
        event_db.clone(),
        escrow_db.clone(),
        escrow_config.out_of_order_timeout,
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
        escrow_config.partially_signed_timeout,
    ));
    bus.register_observer(ps_escrow.clone(), vec![JustNotification::PartiallySigned]);

    let pw_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        event_db.clone(),
        escrow_db.clone(),
        escrow_config.partially_witnessed_timeout,
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
            escrow_config.trans_receipt_timeout,
        )),
        vec![
            JustNotification::KeyEventAdded,
            JustNotification::TransReceiptOutOfOrder,
        ],
    );

    let delegation_escrow = Arc::new(DelegationEscrow::new(
        event_db,
        escrow_db,
        escrow_config.delegation_timeout,
    ));
    bus.register_observer(
        delegation_escrow.clone(),
        vec![
            JustNotification::MissingDelegatingEvent,
            JustNotification::KeyEventAdded,
        ],
    );

    (bus, (ooo_escrow, ps_escrow, pw_escrow, delegation_escrow))
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

    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Option<SignedEventMessage> {
        self.escrowed_out_of_order.get(id).and_then(|mut events| {
            events.find(|event| {
                event.event_message.data.sn == sn
                    && &event.event_message.data.prefix == id
                    && &event.event_message.get_digest() == event_digest
            })
        })
    }
}
impl Notifier for OutOfOrderEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                let id = ev_message.event_message.data.get_prefix();
                self.process_out_of_order_events(bus, &id)?;
            }
            Notification::OutOfOrder(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    let id = signed_event.event_message.data.get_prefix();
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
        event: KeriEvent<KeyEvent>,
    ) -> Option<impl DoubleEndedIterator<Item = SignedEventMessage>> {
        let id = event.data.get_prefix();
        self.escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(move |ev| ev.event_message == event))
    }

    fn remove_partially_signed(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Error> {
        let id = event.data.get_prefix();
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
        let id = signed_event.event_message.data.get_prefix();
        if let Some(esc) = self
            .escrowed_partially_signed
            .get(&id)
            .map(|events| events.filter(|event| event.event_message == signed_event.event_message))
        {
            let mut signatures = esc.flat_map(|ev| ev.signatures).collect::<Vec<_>>();
            let signatures_from_event = signed_event.signatures.clone();
            let without_duplicates = signatures_from_event
                .into_iter()
                .filter(|sig| !signatures.contains(sig))
                .collect::<Vec<_>>();

            signatures.append(&mut without_duplicates.clone());

            let new_event = SignedEventMessage {
                signatures,
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
                Err(Error::NotEnoughReceiptsError) => {
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::PartiallyWitnessed(new_event))?;
                }
                Err(Error::MissingDelegatingEventError)
                | Err(Error::MissingDelegatorSealError(_)) => {
                    // remove from escrow
                    self.remove_partially_signed(&new_event.event_message)?;
                    bus.notify(&Notification::MissingDelegatingEvent(new_event))?;
                }
                Err(Error::SignatureVerificationError) => {
                    // ignore
                }
                Err(Error::NotEnoughSigsError) => {
                    //keep in escrow and save new partially signed event
                    let to_add = SignedEventMessage {
                        signatures: without_duplicates,
                        ..signed_event.to_owned()
                    };
                    self.escrowed_partially_signed.add(&id, to_add)?;
                }
                Err(_e) => {
                    // keep in escrow
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
    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Option<SignedEventMessage> {
        self.escrowed_partially_witnessed
            .get(id)
            .and_then(|mut events| {
                events.find(|event| {
                    event.event_message.data.sn == sn
                        && &event.event_message.data.prefix == id
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
            r.filter(|rct| rct.body.sn == sn && &rct.body.receipted_event_digest == digest)
                // TODO avoid collect
                .collect()
        })
    }

    pub fn get_partially_witnessed_events(&self) -> Vec<SignedEventMessage> {
        match self.escrowed_partially_witnessed.get_all() {
            Some(events) => events.collect(),
            None => vec![],
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
            self.escrowed_nontranferable_receipts
                .add(&id, receipt.clone())?;
            bus.notify(&Notification::ReceiptEscrowed)
        }
    }

    fn accept_receipts_for(&self, event: &SignedEventMessage) -> Result<(), Error> {
        let id = event.event_message.data.get_prefix();
        Ok(self
            .get_escrowed_receipts(
                &id,
                event.event_message.data.get_sn(),
                &event.event_message.get_digest(),
            )
            .unwrap_or_default()
            .into_iter()
            .try_for_each(|receipt| {
                self.escrowed_nontranferable_receipts
                    .remove(&id, &receipt)?;
                self.db.add_receipt_nt(receipt.clone(), &id)
            })?)
    }

    /// Returns receipt couplets of event
    fn get_receipt_couplets(
        &self,
        rct: &SignedNontransferableReceipt,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<(BasicPrefix, SelfSigningPrefix)>, Error> {
        let (mut indexed, mut couplets) = (vec![], vec![]);
        rct.signatures.iter().for_each(|signature| match signature {
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

        Ok(couplets.into_iter().chain(indexes?.into_iter()).collect())
    }

    /// Verify escrowed receipts and remove those with wrong
    /// signatures.
    pub fn validate_receipt(
        &self,
        rct: &SignedNontransferableReceipt,
        receipted_event: &SignedEventMessage,
        witnesses: &[BasicPrefix],
    ) -> Result<(), Error> {
        // verify receipts signatuers
        let serialized_event = receipted_event.event_message.encode()?;
        self.get_receipt_couplets(rct, witnesses)?
            .into_iter()
            .map(|(witness, signature)| {
                if witness.verify(&serialized_event, &signature)? {
                    Ok(())
                } else {
                    Err(Error::SignatureVerificationError)
                }
            })
            .collect::<Result<(), Error>>()
            .map_err(|e| {
                // remove from escrow if any signature is wrong
                match self
                    .escrowed_nontranferable_receipts
                    .remove(&rct.body.prefix, rct)
                {
                    Ok(_) => e,
                    Err(e) => e.into(),
                }
            })
    }

    pub fn validate_partialy_witnessed(
        &self,
        receipted_event: &SignedEventMessage,
        additional_receipt: Option<SignedNontransferableReceipt>,
    ) -> Result<(), Error> {
        let storage = EventStorage::new(self.db.clone());
        let id = receipted_event.event_message.data.get_prefix();
        let sn = receipted_event.event_message.data.get_sn();
        let digest = receipted_event.event_message.get_digest();
        let new_state = storage
            .get_state(&id)?
            .unwrap_or_default()
            .apply(receipted_event)?;

        // Verify additional receipt signature
        if let Some(ref receipt) = additional_receipt {
            let couplets =
                self.get_receipt_couplets(receipt, &new_state.witness_config.witnesses)?;
            couplets
                .iter()
                .map(|(bp, sp)| {
                    bp.verify(&receipted_event.event_message.encode()?, sp)?
                        .then(|| ())
                        .ok_or(Error::ReceiptVerificationError)
                })
                .collect::<Result<_, _>>()?;
        }
        // Verify receipted event signatures
        new_state
            .current
            .verify(
                &receipted_event.event_message.encode()?,
                &receipted_event.signatures,
            )?
            .then(|| ())
            .ok_or(Error::SignatureVerificationError)?;

        // Verify signatures of all receipts and remove those with wrong signatures
        let (couplets, indexed) = self
            .get_escrowed_receipts(&id, sn, &digest)
            .unwrap_or_default()
            .into_iter()
            .filter(|rct| {
                let rr = self.validate_receipt(
                    &rct,
                    &receipted_event,
                    &new_state.witness_config.witnesses,
                );
                rr.is_ok()
            })
            .chain(if let Some(rct) = additional_receipt {
                vec![rct]
            } else {
                Vec::default()
            })
            .fold(
                (vec![], vec![]),
                |(mut all_couplets, mut all_indexed), snr| {
                    snr.signatures.into_iter().for_each(|signature| {
                        match signature {
                            Nontransferable::Indexed(indexed_sigs) => {
                                all_indexed.append(&mut indexed_sigs.clone())
                            }
                            Nontransferable::Couplet(couplets_sigs) => {
                                all_couplets.append(&mut couplets_sigs.clone())
                            }
                        };
                    });
                    (all_couplets, all_indexed)
                },
            );
        // check if there is enough of receipts
        new_state
            .witness_config
            .enough_receipts(couplets, indexed)?
            .then(|| ())
            .ok_or(Error::NotEnoughReceiptsError)
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
                                // accept event and remove receipts
                                self.db
                                    .add_kel_finalized_event(receipted_event.clone(), &id)?;
                                // remove from escrow
                                self.escrowed_partially_witnessed
                                    .remove(&id, &receipted_event)?;
                                // accept receipts and remove them from escrow
                                self.accept_receipts_for(&receipted_event)?;
                                self.db.add_receipt_nt(ooo.to_owned(), &id)?;
                                bus.notify(&Notification::KeyEventAdded(receipted_event))?;
                            }
                            Err(Error::SignatureVerificationError) => {
                                // remove from escrow
                                self.escrowed_partially_witnessed
                                    .remove(&id, &receipted_event)?;
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
                            self.escrowed_partially_witnessed
                                .add(&id, signed_event.clone())?;
                        }
                        Err(Error::SignatureVerificationError) => (),
                        Err(_) => {
                            self.escrowed_partially_witnessed
                                .add(&id, signed_event.clone())?;
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
                self.process_t_receipts_escrow(&event.event_message.data.get_prefix(), bus)?;
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

/// Stores delegated events until delegating event is provided
pub struct DelegationEscrow {
    db: Arc<SledEventDatabase>,
    pub delegation_escrow: Escrow<SignedEventMessage>,
}

impl DelegationEscrow {
    pub fn new(db: Arc<SledEventDatabase>, escrow_db: Arc<EscrowDb>, duration: Duration) -> Self {
        let escrow = Escrow::new(b"dees", duration, escrow_db);
        Self {
            db,
            delegation_escrow: escrow,
        }
    }

    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        delegator_id: &IdentifierPrefix,
        event_digest: &SelfAddressingPrefix,
    ) -> Option<SignedEventMessage> {
        self.delegation_escrow
            .get(delegator_id)
            .and_then(|mut events| {
                events.find(|event| {
                    event.event_message.data.sn == sn
                        && &event.event_message.get_digest() == event_digest
                })
            })
    }
}

impl Notifier for DelegationEscrow {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                // delegator's prefix
                let id = ev_message.event_message.data.get_prefix();
                // get anchored data
                let anchored_data: Vec<Seal> = match &ev_message.event_message.data.event_data {
                    EventData::Icp(icp) => icp.data.clone(),
                    EventData::Rot(rot) => rot.data.clone(),
                    EventData::Ixn(ixn) => ixn.data.clone(),
                    EventData::Dip(dip) => dip.inception_data.data.clone(),
                    EventData::Drt(drt) => drt.data.clone(),
                };

                let seals: Vec<EventSeal> = anchored_data
                    .into_iter()
                    .filter_map(|seal| match seal {
                        Seal::Event(es) => Some(es),
                        _ => None,
                    })
                    .collect();
                if !seals.is_empty() {
                    let potential_delegator_seal = SourceSeal {
                        sn: ev_message.event_message.data.get_sn(),
                        digest: ev_message.event_message.get_digest(),
                    };
                    self.process_delegation_events(bus, &id, seals, potential_delegator_seal)?;
                }
            }
            Notification::MissingDelegatingEvent(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    let delegators_id = match &signed_event.event_message.data.event_data {
                        EventData::Dip(dip) => dip.delegator.clone(),
                        EventData::Drt(_drt) => {
                            let storage = EventStorage::new(self.db.clone());
                            storage
                                .get_state(&signed_event.event_message.data.get_prefix())?
                                .ok_or(Error::MissingDelegatingEventError)?
                                .delegator
                                .ok_or(Error::MissingDelegatingEventError)?
                        }
                        _ => {
                            // not delegated event
                            todo!()
                        }
                    };
                    self.delegation_escrow
                        .add(&delegators_id, signed_event.clone())?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

impl DelegationEscrow {
    pub fn process_delegation_events(
        &self,
        bus: &NotificationBus,
        delegator_id: &IdentifierPrefix,
        anchored_seals: Vec<EventSeal>,
        potential_delegator_seal: SourceSeal,
    ) -> Result<(), Error> {
        if let Some(esc) = self.delegation_escrow.get(delegator_id) {
            for event in esc {
                let seal = anchored_seals.iter().find(|seal| {
                    seal.event_digest == event.event_message.get_digest()
                        && seal.sn == event.event_message.data.get_sn()
                        && seal.prefix == event.event_message.data.get_prefix()
                });
                let delegated_event = match seal {
                    Some(_s) => SignedEventMessage {
                        delegator_seal: Some(potential_delegator_seal.clone()),
                        ..event.clone()
                    },
                    None => event.clone(),
                };
                let validator = EventValidator::new(self.db.clone());
                match validator.validate_event(&delegated_event) {
                    Ok(_) => {
                        // add to kel
                        let child_id = event.event_message.data.get_prefix();
                        self.db
                            .add_kel_finalized_event(delegated_event.clone(), &child_id)?;
                        // remove from escrow
                        self.delegation_escrow.remove(delegator_id, &event)?;
                        bus.notify(&Notification::KeyEventAdded(event))?;
                        // stop processing the escrow if kel was updated. It needs to start again.
                        break;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.delegation_escrow.remove(delegator_id, &event)?;
                    }
                    Err(Error::NotEnoughReceiptsError) => {
                        // remove from escrow
                        self.delegation_escrow.remove(delegator_id, &event)?;
                        bus.notify(&Notification::PartiallyWitnessed(delegated_event))?;
                    }
                    Err(_e) => (), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}
