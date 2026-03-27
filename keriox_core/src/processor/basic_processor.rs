use std::sync::Arc;

use super::{
    notification::{JustNotification, Notification, NotificationBus, Notifier},
    validator::EventValidator,
    EventProcessor, Processor,
};
#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    database::EventDatabase,
    error::Error,
    event_message::signed_event_message::{Notice, SignedEventMessage},
};

pub struct BasicProcessor<D: EventDatabase>(EventProcessor<D>);

impl<D: EventDatabase + 'static> Processor for BasicProcessor<D> {
    type Database = D;
    fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notification: &[JustNotification],
    ) -> Result<(), Error> {
        self.0.register_observer(observer, notification.to_vec())
    }

    fn process_notice(&self, notice: &Notice) -> Result<(), Error> {
        self.0
            .process_notice(notice, BasicProcessor::basic_processing_strategy)?;
        Ok(())
    }

    #[cfg(feature = "query")]
    fn process_op_reply(&self, reply: &SignedReply) -> Result<(), Error> {
        self.0.process_op_reply(reply)?;
        Ok(())
    }
}

impl<D: EventDatabase + 'static> BasicProcessor<D> {
    pub fn new(db: Arc<D>, notification_bus: Option<NotificationBus>) -> Self {
        let processor = EventProcessor::new(notification_bus.unwrap_or_default(), db.clone());
        Self(processor)
    }

    fn basic_processing_strategy(
        events_db: Arc<D>,
        publisher: &NotificationBus,
        signed_event: SignedEventMessage,
    ) -> Result<(), Error> {
        let id = &signed_event.event_message.data.get_prefix();
        let validator = EventValidator::new(events_db.clone());
        match validator.validate_event(&signed_event) {
            Ok(_) => {
                events_db
                    .add_kel_finalized_event(signed_event.clone(), id)
                    .map_err(|_e| Error::DbError)?;
                publisher.notify(&Notification::KeyEventAdded(signed_event))
            }
            Err(Error::EventOutOfOrderError) => {
                publisher.notify(&Notification::OutOfOrder(signed_event))
            }
            Err(Error::NotEnoughReceiptsError) => {
                publisher.notify(&Notification::PartiallyWitnessed(signed_event))
            }
            Err(Error::NotEnoughSigsError) => {
                publisher.notify(&Notification::PartiallySigned(signed_event))
            }
            Err(Error::EventDuplicateError) => {
                publisher.notify(&Notification::DupliciousEvent(signed_event))
            }
            Err(Error::MissingDelegatingEventError | Error::MissingDelegatorSealError(_)) => {
                publisher.notify(&Notification::MissingDelegatingEvent(signed_event))
            }
            Err(e) => Err(e),
        }
    }
}
