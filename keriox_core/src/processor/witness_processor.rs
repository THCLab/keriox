use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::signed_event_message::{Message, SignedEventMessage},
    processor::notification::{JustNotification, NotificationBus},
};

use super::{notification::Notification, validator::EventValidator, EventProcessor, Processor};

pub struct WitnessProcessor(EventProcessor);

impl Processor for WitnessProcessor {
    fn process(&self, message: Message) -> Result<(), Error> {
        self.process(message)
    }

    fn new(db: Arc<SledEventDatabase>) -> Self {
        Self::new(db)
    }

    fn register_observer(
        &mut self,
        observer: Arc<dyn super::notification::Notifier + Send + Sync>,
    ) -> Result<(), Error> {
        self.0.register_observer(observer)
    }
}

impl WitnessProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        use crate::processor::escrow::{OutOfOrderEscrow, PartiallySignedEscrow};
        let mut bus = NotificationBus::new();
        bus.register_observer(
            Arc::new(PartiallySignedEscrow::new(db.clone())),
            vec![JustNotification::PartiallySigned],
        );
        bus.register_observer(
            Arc::new(OutOfOrderEscrow::new(db.clone())),
            vec![
                JustNotification::OutOfOrder,
                JustNotification::KeyEventAdded,
            ],
        );
        let processor = EventProcessor::new(db, bus);
        Self(processor)
    }

    fn witness_processing_strategy(
        db: Arc<SledEventDatabase>,
        publisher: &NotificationBus,
        signed_event: SignedEventMessage,
    ) -> Result<(), Error> {
        let id = &signed_event.event_message.event.get_prefix();
        let validator = EventValidator::new(db.clone());
        match validator.validate_event(&signed_event) {
            Ok(_) => {
                db.add_kel_finalized_event(signed_event.clone(), id)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::EventOutOfOrderError) => {
                publisher.notify(&Notification::OutOfOrder(signed_event))
            }
            Err(Error::NotEnoughReceiptsError) => {
                db.add_kel_finalized_event(signed_event.clone(), id)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::NotEnoughSigsError) => {
                publisher.notify(&Notification::PartiallySigned(signed_event))
            }
            Err(Error::EventDuplicateError) => {
                db.add_duplicious_event(signed_event.clone(), id)?;
                publisher.notify(&Notification::DupliciousEvent(signed_event))
            }
            Err(e) => Err(e),
        }
    }

    /// Process
    ///
    /// Process a deserialized KERI message.
    /// Ignore not fully witness error and accept not fully witnessed events.
    pub fn process(&self, message: Message) -> Result<(), Error> {
        self.0
            .process(message, WitnessProcessor::witness_processing_strategy)?;
        Ok(())
    }
}
