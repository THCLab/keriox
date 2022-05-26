use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::signed_event_message::Message,
    processor::{notification::NotificationBus, JustNotification},
};

use super::{notification::Notification, EventProcessor};

pub struct WitnessProcessor(EventProcessor);

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
        let processor = EventProcessor::new(db);
        Self(processor)
    }

    /// Process
    ///
    /// Process a deserialized KERI message.
    /// Ignore not fully witness error and accept not fully witnessed events.
    pub fn process(&self, message: Message) -> Result<Notification, Error> {
        let res = self.0.process(message)?;
        if let Notification::PartiallyWitnessed(signed_event) = res {
            let id = &signed_event.event_message.event.get_prefix();
            self.0
                .db
                .add_kel_finalized_event(signed_event.clone(), id)?;
            Ok(Notification::KeyEventAdded(signed_event))
        } else {
            Ok(res)
        }
    }
}
