pub mod delegation_escrow;
pub mod maybe_out_of_order_escrow;
pub mod partially_signed_escrow;
pub mod partially_witnessed_escrow;

use std::{fmt::Debug, sync::Arc, time::Duration};

use delegation_escrow::DelegationEscrow;
use maybe_out_of_order_escrow::MaybeOutOfOrderEscrow;
use partially_signed_escrow::PartiallySignedEscrow;
use partially_witnessed_escrow::PartiallyWitnessedEscrow;

use super::{
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
    event_message::signed_event_message::SignedTransferableReceipt,
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
