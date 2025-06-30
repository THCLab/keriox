pub mod delegation_escrow;
pub mod duplicitous_events;
pub mod maybe_out_of_order_escrow;
pub mod partially_signed_escrow;
pub mod partially_witnessed_escrow;
#[cfg(feature = "query")]
pub mod reply_escrow;

use std::{fmt::Debug, sync::Arc, time::Duration};

use delegation_escrow::DelegationEscrow;
use duplicitous_events::DuplicitousEvents;
use maybe_out_of_order_escrow::MaybeOutOfOrderEscrow;
use partially_signed_escrow::PartiallySignedEscrow;
use partially_witnessed_escrow::PartiallyWitnessedEscrow;

use super::notification::{JustNotification, NotificationBus};
use crate::database::{EscrowCreator, EventDatabase};

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

pub fn default_escrow_bus<D>(
    event_db: Arc<D>,
    escrow_config: EscrowConfig,
) -> (
    NotificationBus,
    (
        Arc<MaybeOutOfOrderEscrow<D>>,
        Arc<PartiallySignedEscrow<D>>,
        Arc<PartiallyWitnessedEscrow<D>>,
        Arc<DelegationEscrow<D>>,
        Arc<DuplicitousEvents<D>>,
    ),
) where D: EventDatabase + EscrowCreator + Sync + Send + 'static {
    let mut bus = NotificationBus::new();

    // Register out of order escrow, to save and reprocess out of order events
    let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
        event_db.clone(),
        escrow_config.out_of_order_timeout,
    ));
    println!("Registering out of order escrow with timeout: {:?}", escrow_config.out_of_order_timeout);
    bus.register_observer(
        ooo_escrow.clone(),
        vec![
            JustNotification::OutOfOrder,
            JustNotification::KeyEventAdded,
        ],
    );

    let ps_escrow = Arc::new(PartiallySignedEscrow::new(
        event_db.clone(),
        escrow_config.partially_signed_timeout,
    ));
    bus.register_observer(ps_escrow.clone(), vec![JustNotification::PartiallySigned]);

    let pw_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        event_db.clone(),
        event_db.get_log_db(),
        escrow_config.partially_witnessed_timeout,
    ));
    bus.register_observer(
        pw_escrow.clone(),
        vec![
            JustNotification::PartiallyWitnessed,
            JustNotification::ReceiptOutOfOrder,
        ],
    );

    let delegation_escrow = Arc::new(DelegationEscrow::new(
        event_db.clone(),
        escrow_config.delegation_timeout,
    ));
    bus.register_observer(
        delegation_escrow.clone(),
        vec![
            JustNotification::MissingDelegatingEvent,
            JustNotification::KeyEventAdded,
        ],
    );

    let dup = Arc::new(DuplicitousEvents::new(event_db));
    bus.register_observer(dup.clone(), vec![JustNotification::DuplicitousEvent]);

    (
        bus,
        (ooo_escrow, ps_escrow, pw_escrow, delegation_escrow, dup),
    )
}
