use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase, error::Error, event_message::signed_event_message::Message,
    state::IdentifierState, processor::JustNotification,
};

use super::{compute_state, escrow::Notification, EventProcessor};

pub struct WitnessProcessor(EventProcessor);

impl WitnessProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        use crate::processor::escrow::{OutOfOrderEscrow, PartiallySignedEscrow};
        let mut processor = EventProcessor::new(db.clone());
        processor.register_observer(PartiallySignedEscrow::new(db.clone()), vec![JustNotification::PartiallySigned]);
        processor.register_observer(OutOfOrderEscrow::new(db), vec![JustNotification::OutOfOrder, JustNotification::KeyEventAdded]);
        Self(processor)
    }

    /// Process
    ///
    /// Process a deserialized KERI message.
    /// Ignore not fully witness error and accept not fully witnessed events.
    pub fn process(&self, message: Message) -> Result<Option<IdentifierState>, Error> {
        let res = self.0.process(message.clone());
        if let (Err(Error::NotEnoughReceiptsError), Message::Event(signed_event)) = (&res, message)
        {
            let id = &signed_event.event_message.event.get_prefix();
            self.0.db.add_kel_finalized_event(signed_event, id)?;
            self.0.notify(&Notification::KeyEventAdded(id.clone()))?;
            Ok(compute_state(self.0.db.clone(), id)?)
        } else {
            res
        }
    }
}
