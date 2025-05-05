use std::sync::Arc;

use crate::{
    database::redb::{escrow_database::SnKeyDatabase, RedbDatabase},
    error::Error,
    event_message::signed_event_message::SignedEventMessage,
    prefix::IdentifierPrefix,
    processor::notification::{Notification, NotificationBus, Notifier},
};

use super::maybe_out_of_order_escrow::SnKeyEscrow;

pub struct DuplicitousEvents {
    pub(crate) events: SnKeyEscrow,
}

impl DuplicitousEvents {
    pub fn new(db: Arc<RedbDatabase>) -> Self {
        let escrow_db = SnKeyEscrow::new(
            Arc::new(SnKeyDatabase::new(db.db.clone(), "duplicitous_escrow").unwrap()),
            db.log_db.clone(),
        );
        Self { events: escrow_db }
    }
}

impl Notifier for DuplicitousEvents {
    fn notify(&self, notification: &Notification, _bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::DupliciousEvent(ev_message) => {
                self.events.insert(ev_message)?;
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

impl DuplicitousEvents {
    pub fn get(&self, id: &IdentifierPrefix) -> Result<Vec<SignedEventMessage>, Error> {
        self.events
            .get_from_sn(id, 0)
            .map_err(|_| Error::DbError)
            .map(|v| v.collect())
    }
}
