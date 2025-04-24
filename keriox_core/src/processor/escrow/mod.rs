pub mod maybe_out_of_order_escrow;
pub mod partially_witnessed_escrow;
pub mod partially_signed_escrow;

use std::{fmt::Debug, sync::Arc, time::Duration};

use maybe_out_of_order_escrow::MaybeOutOfOrderEscrow;
use partially_signed_escrow::PartiallySignedEscrow;
use partially_witnessed_escrow::PartiallyWitnessedEscrow;
use said::SelfAddressingIdentifier;

use super::{
    event_storage::EventStorage,
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
};
use crate::{
    database::{
        escrow::{Escrow, EscrowDb},
        redb::RedbDatabase,
        sled::SledEventDatabase,
        EventDatabase,
    },
    error::Error,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal, SourceSeal},
        KeyEvent,
    },
    event_message::{
        msg::KeriEvent,
        signed_event_message::{SignedEventMessage, SignedTransferableReceipt},
    },
    prefix::IdentifierPrefix,
};
#[cfg(feature = "query")]
use crate::{
    processor::validator::{MoreInfoError, VerificationError},
    query::reply_event::ReplyRoute,
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
    event_db: Arc<RedbDatabase>,
    sled_db: Arc<SledEventDatabase>,
    escrow_db: Arc<EscrowDb>,
    escrow_config: EscrowConfig,
) -> (
    NotificationBus,
    (
        Arc<MaybeOutOfOrderEscrow>,
        Arc<PartiallySignedEscrow<RedbDatabase>>,
        Arc<PartiallyWitnessedEscrow>,
        Arc<DelegationEscrow<RedbDatabase>>,
    ),
) {
    let mut bus = NotificationBus::new();

    // Register out of order escrow, to save and reprocess out of order events
    let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
        event_db.clone(),
        sled_db.clone(),
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
        sled_db.clone(),
        escrow_db.clone(),
        escrow_config.partially_signed_timeout,
    ));
    bus.register_observer(ps_escrow.clone(), vec![JustNotification::PartiallySigned]);

    let pw_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        event_db.clone(),
        sled_db.clone(),
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
            sled_db.clone(),
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
        sled_db,
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

pub struct TransReceiptsEscrow<D: EventDatabase> {
    db: Arc<D>,
    old_db: Arc<SledEventDatabase>,
    pub(crate) escrowed_trans_receipts: Escrow<SignedTransferableReceipt>,
}
impl<D: EventDatabase> TransReceiptsEscrow<D> {
    pub fn new(
        db: Arc<D>,
        sled_db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
    ) -> Self {
        Self {
            db,
            old_db: sled_db,
            escrowed_trans_receipts: Escrow::new(b"vres", duration, escrow_db.clone()),
        }
    }
}
impl<D: EventDatabase> Notifier for TransReceiptsEscrow<D> {
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
impl<D: EventDatabase> TransReceiptsEscrow<D> {
    pub fn process_t_receipts_escrow(
        &self,
        id: &IdentifierPrefix,
        bus: &NotificationBus,
    ) -> Result<(), Error> {
        if let Some(esc) = self.escrowed_trans_receipts.get(id) {
            for timestamped_receipt in esc {
                let validator = EventValidator::new(self.old_db.clone(), self.db.clone());
                match validator.validate_validator_receipt(&timestamped_receipt) {
                    Ok(_) => {
                        // add to receipts
                        self.db
                            .add_receipt_t(timestamped_receipt.clone(), id)
                            .map_err(|_| Error::DbError)?;
                        // remove from escrow
                        self.escrowed_trans_receipts
                            .remove(id, &timestamped_receipt)?;
                        bus.notify(&Notification::ReceiptAccepted)?;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.escrowed_trans_receipts
                            .remove(id, &timestamped_receipt)?;
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
pub struct ReplyEscrow<D: EventDatabase> {
    events_db: Arc<D>,
    escrow_db: Arc<SledEventDatabase>,
}

#[cfg(feature = "query")]
impl<D: EventDatabase> ReplyEscrow<D> {
    pub fn new(db: Arc<SledEventDatabase>, events_db: Arc<D>) -> Self {
        Self {
            escrow_db: db,
            events_db,
        }
    }
}
#[cfg(feature = "query")]
impl<D: EventDatabase> Notifier for ReplyEscrow<D> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KsnOutOfOrder(rpy) => {
                if let ReplyRoute::Ksn(_id, ksn) = rpy.reply.get_route() {
                    self.escrow_db
                        .add_escrowed_reply(rpy.clone(), &ksn.state.prefix)?;
                };
                Ok(())
            }
            &Notification::KeyEventAdded(_) => self.process_reply_escrow(bus),
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "query")]
impl<D: EventDatabase> ReplyEscrow<D> {
    pub fn process_reply_escrow(&self, _bus: &NotificationBus) -> Result<(), Error> {
        use crate::query::QueryError;

        if let Some(esc) = self.escrow_db.get_all_escrowed_replys() {
            for sig_rep in esc {
                let validator = EventValidator::new(self.escrow_db.clone(), self.events_db.clone());
                let id = if let ReplyRoute::Ksn(_id, ksn) = sig_rep.reply.get_route() {
                    Ok(ksn.state.prefix)
                } else {
                    Err(Error::SemanticError("Wrong event type".into()))
                }?;
                match validator.process_signed_ksn_reply(&sig_rep) {
                    Ok(_) => {
                        self.escrow_db.remove_escrowed_reply(&id, &sig_rep)?;
                        self.escrow_db.update_accepted_reply(sig_rep, &id)?;
                    }
                    Err(Error::SignatureVerificationError)
                    | Err(Error::QueryError(QueryError::StaleRpy)) => {
                        // remove from escrow
                        self.escrow_db.remove_escrowed_reply(&id, &sig_rep)?;
                    }
                    Err(Error::EventOutOfOrderError)
                    | Err(Error::VerificationError(VerificationError::MoreInfo(
                        MoreInfoError::EventNotFound(_),
                    ))) => (), // keep in escrow,
                    Err(e) => return Err(e),
                };
            }
        };
        Ok(())
    }
}

/// Stores delegated events until delegating event is provided
pub struct DelegationEscrow<D: EventDatabase> {
    db: Arc<D>,
    sled_db: Arc<SledEventDatabase>,
    pub delegation_escrow: Escrow<SignedEventMessage>,
}

impl<D: EventDatabase> DelegationEscrow<D> {
    pub fn new(
        db: Arc<D>,
        sled_db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        duration: Duration,
    ) -> Self {
        let escrow = Escrow::new(b"dees", duration, escrow_db);
        Self {
            db,
            sled_db,
            delegation_escrow: escrow,
        }
    }

    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        delegator_id: &IdentifierPrefix,
        event_digest: &SelfAddressingIdentifier,
    ) -> Option<SignedEventMessage> {
        self.delegation_escrow
            .get(delegator_id)
            .and_then(|mut events| {
                events.find(|event| {
                    event.event_message.data.sn == sn
                        && event.event_message.digest().ok().as_ref() == Some(event_digest)
                })
            })
    }
}

impl<D: EventDatabase> Notifier for DelegationEscrow<D> {
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
                    let potential_delegator_seal = SourceSeal::new(
                        ev_message.event_message.data.get_sn(),
                        ev_message.event_message.digest()?,
                    );
                    self.process_delegation_events(bus, &id, seals, potential_delegator_seal)?;
                }
            }
            Notification::MissingDelegatingEvent(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    let delegators_id = match &signed_event.event_message.data.event_data {
                        EventData::Dip(dip) => Ok(dip.delegator.clone()),
                        EventData::Drt(_drt) => {
                            let storage = EventStorage::new(self.db.clone(), self.sled_db.clone());
                            storage
                                .get_state(&signed_event.event_message.data.get_prefix())
                                .ok_or(Error::MissingDelegatingEventError)?
                                .delegator
                                .ok_or(Error::MissingDelegatingEventError)
                        }
                        _ => {
                            // not delegated event
                            Err(Error::SemanticError("Not delegated event".to_string()))
                        }
                    }?;
                    self.delegation_escrow
                        .add(&delegators_id, signed_event.clone())?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

impl<D: EventDatabase> DelegationEscrow<D> {
    pub fn process_delegation_events(
        &self,
        bus: &NotificationBus,
        delegator_id: &IdentifierPrefix,
        anchored_seals: Vec<EventSeal>,
        potential_delegator_seal: SourceSeal,
    ) -> Result<(), Error> {
        if let Some(esc) = self.delegation_escrow.get(delegator_id) {
            for event in esc {
                let event_digest = event.event_message.digest()?;
                let seal = anchored_seals.iter().find(|seal| {
                    seal.event_digest() == event_digest
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
                let validator = EventValidator::new(self.sled_db.clone(), self.db.clone());
                match validator.validate_event(&delegated_event) {
                    Ok(_) => {
                        // add to kel
                        let child_id = event.event_message.data.get_prefix();
                        self.db
                            .add_kel_finalized_event(delegated_event.clone(), &child_id)
                            .map_err(|_| Error::DbError)?;
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
