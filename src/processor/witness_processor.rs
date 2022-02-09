use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase, error::Error, event_message::signed_event_message::Message,
    state::IdentifierState,
};

use super::{compute_state, escrow::Notification, EventProcessor};

pub struct WitnessProcessor(EventProcessor);

impl WitnessProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        use crate::processor::escrow::{NontransReceiptsEscrow, OutOfOrderEscrow};
        let mut processor = EventProcessor::new(db);
        processor.register_escrow(Box::new(OutOfOrderEscrow::default()));
        processor.register_escrow(Box::new(NontransReceiptsEscrow::default()));
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
            self.0
                .notify(&Notification::KelUpdated(id.clone()))
                .unwrap();
            Ok(compute_state(self.0.db.clone(), id)?)
        } else {
            res
        }
    }
}
