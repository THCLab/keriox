use keri_core::{
    database::{redb::RedbDatabase, EventDatabase},
    error::Error,
    event_message::signed_event_message::{Notice, SignedEventMessage},
    processor::{
        escrow::{
            delegation_escrow::DelegationEscrow, maybe_out_of_order_escrow::MaybeOutOfOrderEscrow,
            partially_signed_escrow::PartiallySignedEscrow, EscrowConfig,
        },
        notification::{JustNotification, Notification, NotificationBus, Notifier},
        validator::EventValidator,
        EventProcessor, Processor,
    },
    query::reply_event::SignedReply,
};
use std::{sync::Arc, time::Duration};

pub struct WitnessProcessor {
    processor: EventProcessor<<WitnessProcessor as keri_core::processor::Processor>::Database>,
}

impl Processor for WitnessProcessor {
    type Database = RedbDatabase;
    fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: &[JustNotification],
    ) -> Result<(), Error> {
        self.processor
            .register_observer(observer, notifications.to_vec())
    }

    fn process_notice(&self, notice: &Notice) -> Result<(), Error> {
        self.processor
            .process_notice(notice, WitnessProcessor::witness_processing_strategy)?;
        Ok(())
    }

    fn process_op_reply(&self, reply: &SignedReply) -> Result<(), Error> {
        self.processor.process_op_reply(reply)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct WitnessEscrowConfig {
    pub partially_signed_timeout: Duration,
    pub out_of_order_timeout: Duration,
    pub delegation_timeout: Duration,
}

impl Default for WitnessEscrowConfig {
    fn default() -> Self {
        let default = EscrowConfig::default();
        Self {
            partially_signed_timeout: default.partially_signed_timeout,
            out_of_order_timeout: default.out_of_order_timeout,
            delegation_timeout: default.delegation_timeout,
        }
    }
}

impl WitnessProcessor {
    pub fn new(redb: Arc<RedbDatabase>, escrow_config: WitnessEscrowConfig) -> Self {
        let bus = NotificationBus::new();
        let partially_signed_escrow = Arc::new(PartiallySignedEscrow::new(
            redb.clone(),
            escrow_config.partially_signed_timeout,
        ));
        bus.register_observer(
            partially_signed_escrow,
            vec![JustNotification::PartiallySigned],
        );
        let out_of_order_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
            redb.clone(),
            escrow_config.out_of_order_timeout,
        ));
        bus.register_observer(
            out_of_order_escrow,
            vec![
                JustNotification::OutOfOrder,
                JustNotification::KeyEventAdded,
            ],
        );
        let deleating_escrow = Arc::new(DelegationEscrow::new(
            redb.clone(),
            escrow_config.delegation_timeout,
        ));
        bus.register_observer(
            deleating_escrow,
            vec![
                JustNotification::MissingDelegatingEvent,
                JustNotification::KeyEventAdded,
            ],
        );
        let processor = EventProcessor::new(bus, redb.clone());
        Self { processor }
    }

    /// Witness processing strategy
    ///
    /// Ignore not fully witness error and accept not fully witnessed events.
    fn witness_processing_strategy(
        db: Arc<RedbDatabase>,
        publisher: &NotificationBus,
        signed_event: SignedEventMessage,
    ) -> Result<(), Error> {
        let id = &signed_event.event_message.data.get_prefix();
        let validator = EventValidator::new(db.clone());
        match validator.validate_event(&signed_event) {
            Ok(_) => {
                db.add_kel_finalized_event(signed_event.clone(), id)
                    .map_err(|_| Error::DbError)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::EventOutOfOrderError) => {
                publisher.notify(&Notification::OutOfOrder(signed_event))
            }
            Err(Error::MissingDelegatingEventError) => {
                publisher.notify(&Notification::MissingDelegatingEvent(signed_event))
            }
            Err(Error::NotEnoughReceiptsError) => {
                db.add_kel_finalized_event(signed_event.clone(), id)
                    .map_err(|_| Error::DbError)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::NotEnoughSigsError) => {
                publisher.notify(&Notification::PartiallySigned(signed_event))
            }
            Err(Error::EventDuplicateError) => {
                publisher.notify(&Notification::DupliciousEvent(signed_event))
            }
            Err(e) => Err(e),
        }
    }
}
