pub mod delegation_escrow;
pub mod duplicitous_events;
pub mod maybe_out_of_order_escrow;
pub mod partially_signed_escrow;
pub mod partially_witnessed_escrow;
#[cfg(feature = "query")]
pub mod reply_escrow;

use std::{
    fmt::Debug,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use delegation_escrow::DelegationEscrow;
use duplicitous_events::DuplicitousEvents;
use maybe_out_of_order_escrow::MaybeOutOfOrderEscrow;
use partially_signed_escrow::PartiallySignedEscrow;
use partially_witnessed_escrow::PartiallyWitnessedEscrow;

use super::notification::{JustNotification, NotificationBus};
use crate::{
    database::{EscrowCreator, EscrowDatabase, EventDatabase},
    error::Error,
};

/// How long an escrow keeps an event by default: long enough for witness
/// receipts and a delegator's approval to arrive.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// How often at most an escrow looks for stale events.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// Drops the events an escrow has held longer than its timeout, so escrows
/// do not grow without bound. It runs when the escrow is notified, at most
/// once per [`SWEEP_INTERVAL`], so an event is gone at most that long after
/// it timed out.
pub(crate) struct StaleSweep {
    timeout: Duration,
    last: Mutex<Option<Instant>>,
}

impl StaleSweep {
    pub(crate) fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            last: Mutex::new(None),
        }
    }

    pub(crate) fn run<E: EscrowDatabase>(&self, escrow: &E) -> Result<(), Error> {
        let mut last = self.last.lock().map_err(|_| Error::DbError)?;
        if last.is_some_and(|at| at.elapsed() < SWEEP_INTERVAL.min(self.timeout)) {
            return Ok(());
        }
        *last = Some(Instant::now());
        escrow
            .remove_older_than(self.timeout)
            .map_err(|_| Error::DbError)
    }
}

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
            out_of_order_timeout: DEFAULT_TIMEOUT,
            partially_signed_timeout: DEFAULT_TIMEOUT,
            partially_witnessed_timeout: DEFAULT_TIMEOUT,
            trans_receipt_timeout: DEFAULT_TIMEOUT,
            delegation_timeout: DEFAULT_TIMEOUT,
        }
    }
}

pub struct EscrowSet<D: EventDatabase + EscrowCreator> {
    pub out_of_order: Arc<MaybeOutOfOrderEscrow<D>>,
    pub partially_signed: Arc<PartiallySignedEscrow<D>>,
    pub partially_witnessed: Arc<PartiallyWitnessedEscrow<D>>,
    pub delegation: Arc<DelegationEscrow<D>>,
    pub duplicitous: Arc<DuplicitousEvents<D>>,
}

pub fn default_escrow_bus<D>(
    event_db: Arc<D>,
    escrow_config: EscrowConfig,
    notification_bus: Option<NotificationBus>,
) -> (NotificationBus, EscrowSet<D>)
where
    D: EventDatabase + EscrowCreator + Sync + Send + 'static,
{
    let bus = notification_bus.unwrap_or_default();

    // Register out of order escrow, to save and reprocess out of order events
    let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
        event_db.clone(),
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
        EscrowSet {
            out_of_order: ooo_escrow,
            partially_signed: ps_escrow,
            partially_witnessed: pw_escrow,
            delegation: delegation_escrow,
            duplicitous: dup,
        },
    )
}
