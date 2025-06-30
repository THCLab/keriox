use std::sync::Arc;

use crate::{
    database::{redb::{escrow_database::SnKeyDatabase, RedbDatabase}, SequencedEventDatabase, EscrowDatabase},
    error::Error,
    event_message::signed_event_message::SignedEventMessage,
    prefix::IdentifierPrefix,
    processor::notification::{Notification, NotificationBus, Notifier},
};

use super::maybe_out_of_order_escrow::{EscrowCreator, SnKeyEscrow};

pub struct DuplicitousEvents<D: EscrowCreator> {
    pub(crate) events: D::EscrowDatabaseType,
}

impl<D: EscrowCreator> DuplicitousEvents<D> {
    pub fn new(db: Arc<D>) -> Self {
        let escrow_db = db.create_escrow_db("duplicitous_escrow");
        /* let escrow_db = SnKeyEscrow::new(
            Arc::new(SnKeyDatabase::new(db.db.clone(), "duplicitous_escrow").unwrap()),
            db.log_db.clone(),
        ); */
        Self { events: escrow_db }
    }

    pub fn get(&self, id: &IdentifierPrefix) -> Result<Vec<SignedEventMessage>, Error> {
        self.events
            .get_from_sn(id, 0)
            .map_err(|_| Error::DbError)
            .map(|v| v.collect())
    }
}

impl<D: EscrowCreator> Notifier for DuplicitousEvents<D> {
    fn notify(&self, notification: &Notification, _bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::DupliciousEvent(ev_message) => {
                self.events.insert(ev_message).map_err(|_| Error::DbError)?;
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

