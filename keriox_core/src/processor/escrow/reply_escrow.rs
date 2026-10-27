use std::sync::Arc;

use said::SelfAddressingIdentifier;

#[cfg(feature = "storage-redb")]
use crate::database::redb::{
    escrow_database::SnKeyDatabase,
    ksn_log::{AcceptedKsn, KsnLogDatabase},
    RedbDatabase, RedbError,
};
use crate::{
    database::{EventDatabase, SequencedEventDatabase},
    error::Error,
    prefix::IdentifierPrefix,
    processor::{
        notification::{Notification, NotificationBus, Notifier},
        validator::{EventValidator, MoreInfoError, VerificationError},
    },
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

#[cfg(feature = "storage-redb")]
#[derive(Clone)]
pub struct ReplyEscrow<D: EventDatabase> {
    events_db: Arc<D>,
    accepted_ksn: Arc<AcceptedKsn>,
    escrowed_reply: Arc<SnKeyReplyEscrow>,
}

#[cfg(feature = "storage-redb")]
impl ReplyEscrow<RedbDatabase> {
    pub fn new(events_db: Arc<RedbDatabase>) -> Self {
        let acc = Arc::new(AcceptedKsn::new(events_db.db.clone()).unwrap());
        let reply_esc_db = Arc::new(SnKeyReplyEscrow::new(
            Arc::new(SnKeyDatabase::new(events_db.db.clone(), "reply_escrow").unwrap()),
            acc.ksn_log.clone(),
        ));
        Self {
            events_db,
            accepted_ksn: acc,
            escrowed_reply: reply_esc_db,
        }
    }
}
#[cfg(feature = "storage-redb")]
impl Notifier for ReplyEscrow<RedbDatabase> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KsnOutOfOrder(rpy) => {
                match rpy.reply.get_route() {
                    ReplyRoute::Ksn(_id, _ksn) => {
                        self.escrowed_reply.insert(rpy)?;
                    }
                    _ => return Err(Error::SemanticError("Wrong event type".to_string())),
                };
                Ok(())
            }
            Notification::KeyEventAdded(ev) => {
                let id = ev.event_message.data.get_prefix();
                let sn = ev.event_message.data.sn;
                self.process_reply_escrow(bus, &id, sn)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "storage-redb")]
impl ReplyEscrow<RedbDatabase> {
    pub fn process_reply_escrow(
        &self,
        _bus: &NotificationBus,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<(), Error> {
        use crate::query::QueryError;

        for sig_rep in self.escrowed_reply.get_from_sn(id, sn)? {
            let validator = EventValidator::new(self.events_db.clone());
            match validator.process_signed_ksn_reply(&sig_rep) {
                Ok(_) => {
                    self.escrowed_reply.remove(&sig_rep.reply);
                    self.accepted_ksn.insert(sig_rep.clone())?;
                }
                Err(Error::SignatureVerificationError)
                | Err(Error::QueryError(QueryError::StaleRpy)) => {
                    // remove from escrow
                    self.escrowed_reply.remove(&sig_rep.reply);
                }
                Err(Error::EventOutOfOrderError)
                | Err(Error::VerificationError(VerificationError::MoreInfo(
                    MoreInfoError::EventNotFound(_),
                ))) => (), // keep in escrow,
                Err(e) => return Err(e),
            };
        }
        // };
        Ok(())
    }

    pub fn get_all(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, Error> {
        Ok(self.escrowed_reply.get_from_sn(id, 0)?.collect())
    }
}

#[cfg(feature = "storage-redb")]
pub struct SnKeyReplyEscrow {
    escrow: Arc<SnKeyDatabase>,
    log: Arc<KsnLogDatabase>,
}

#[cfg(feature = "storage-redb")]
impl SnKeyReplyEscrow {
    pub(crate) fn new(escrow: Arc<SnKeyDatabase>, log: Arc<KsnLogDatabase>) -> Self {
        Self { escrow, log }
    }

    pub fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &SelfAddressingIdentifier,
    ) -> Result<(), RedbError> {
        self.escrow.insert(id, sn, event_digest)?;

        Ok(())
    }

    pub fn insert(&self, event: &SignedReply) -> Result<(), RedbError> {
        self.log
            .log_reply(&crate::database::redb::WriteTxnMode::CreateNew, &event)?;
        let said = event.reply.digest().unwrap();
        let id = event.reply.get_prefix();
        let sn = match &event.reply.data.data {
            ReplyRoute::Ksn(_identifier_prefix, key_state_notice) => key_state_notice.state.sn,
            _ => return Err(RedbError::WrongValue),
        };
        self.escrow.insert(&id, sn, &said)?;

        Ok(())
    }

    pub fn get_from_sn<'a>(
        &'a self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<impl Iterator<Item = SignedReply> + 'a, RedbError> {
        Ok(self
            .escrow
            .get_greater_than(identifier, sn)?
            .map(move |said| self.log.get_signed_reply(&said).unwrap().unwrap()))
    }

    pub fn remove(&self, event: &ReplyEvent) {
        let said = event.digest().unwrap();
        let id = event.get_prefix();
        let sn = match &event.data.data {
            ReplyRoute::Ksn(_identifier_prefix, key_state_notice) => key_state_notice.state.sn,
            // Only key state notices are escrowed.
            _ => return,
        };
        self.escrow.remove(&id, sn, &said).unwrap();
    }

    pub fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<bool, RedbError> {
        Ok(self
            .escrow
            .get(id, sn)?
            .find(|said| said == digest)
            .is_some())
    }
}

#[cfg(test)]
mod tests {
    use crate::event_message::cesr_adapter::parse_cesr_stream;
    use crate::{
        actor::prelude::{BasicProcessor, Message},
        database::redb::RedbDatabase,
        error::Error,
        event_message::signed_event_message::Op,
        processor::{escrow::reply_escrow::ReplyEscrow, notification::JustNotification, Processor},
    };
    use std::{fs, sync::Arc};
    use tempfile::{Builder, NamedTempFile};

    /// The escrow keeps key state notices only. Any other reply is refused
    /// on insert, and removing one is a no-op, instead of panicking.
    #[test]
    fn a_reply_other_than_a_key_state_notice_is_not_escrowed() {
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let rpy_escrow = ReplyEscrow::new(events_db);

        let loc_scheme = r#"-_AAACAA{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-MAhBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw"#;
        let Ok(Message::Op(Op::Reply(rpy))) =
            Message::try_from(parse_cesr_stream(loc_scheme.as_bytes()).unwrap())
        else {
            panic!("fixture must be a reply")
        };

        assert!(rpy_escrow.escrowed_reply.insert(&rpy).is_err());
        rpy_escrow.escrowed_reply.remove(&rpy.reply);
    }

    #[test]
    pub fn test_reply_escrow() -> Result<(), Error> {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let event_processor = BasicProcessor::new(events_db.clone(), None);
        let rpy_escrow = Arc::new(ReplyEscrow::new(events_db.clone()));
        event_processor.register_observer(
            rpy_escrow.clone(),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::KsnOutOfOrder,
            ],
        )?;

        let fixture = crate::query::key_state_notice::fixtures::kel();
        let identifier = fixture.id.clone();
        let message = |event: &crate::event_message::signed_event_message::SignedEventMessage| {
            Message::Notice(crate::event_message::signed_event_message::Notice::Event(
                event.clone(),
            ))
        };
        let kel_events = fixture.events[..4].iter().map(message);
        let rest_of_kel = fixture.events[4..].iter().map(message);
        let reply = |sn| {
            Message::Op(Op::Reply(
                crate::query::key_state_notice::fixtures::ksn_reply(&fixture, sn),
            ))
        };
        // The notice at sn 3 is signed with the inception's keys, the one at
        // sn 8 with those of the rotation at sn 4.
        let deserialized_old_rpy = reply(3);
        let deserialized_new_rpy = reply(8);

        // Try to process out of order reply
        event_processor
            .process(&deserialized_old_rpy.clone())
            .unwrap();

        let escrow = rpy_escrow
            .escrowed_reply
            .get_from_sn(&identifier, 0)
            .unwrap();
        assert_eq!(escrow.collect::<Vec<_>>().len(), 1);

        let accepted_rpys = rpy_escrow.clone().accepted_ksn.get_all(&identifier)?;
        assert!(accepted_rpys.is_empty());

        // process kel events and update escrow
        // reply event should be unescrowed and save as accepted
        kel_events.for_each(|ev| {
            event_processor.process(&ev).unwrap();
        });

        let escrow = rpy_escrow.escrowed_reply.get_from_sn(&identifier, 0);
        assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

        let accepted_rpys = rpy_escrow.accepted_ksn.get_all(&identifier)?;
        assert_eq!(accepted_rpys.len(), 1);

        // Try to process new out of order reply
        // reply event should be escrowed, accepted reply shouldn't change
        event_processor.process(&deserialized_new_rpy.clone())?;
        let mut escrow = rpy_escrow
            .escrowed_reply
            .get_from_sn(&identifier, 0)
            .unwrap();
        assert_eq!(
            Message::Op(Op::Reply(escrow.next().unwrap())),
            deserialized_new_rpy
        );
        assert!(escrow.next().is_none());

        let accepted_rpys = rpy_escrow.accepted_ksn.get_all(&identifier)?;
        assert_eq!(accepted_rpys.len(), 1);
        assert_eq!(
            Message::Op(Op::Reply(accepted_rpys[0].clone())),
            deserialized_old_rpy
        );

        // process rest of kel and update escrow
        // reply event should be unescrowed and save as accepted
        rest_of_kel.for_each(|ev| {
            event_processor.process(&ev).unwrap();
        });

        let escrow = rpy_escrow.escrowed_reply.get_from_sn(&identifier, 0);
        assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

        let accepted_rpys = rpy_escrow.accepted_ksn.get_all(&identifier)?;

        assert_eq!(accepted_rpys.len(), 1);
        assert_eq!(
            Message::Op(Op::Reply(accepted_rpys[0].clone())),
            deserialized_new_rpy
        );

        Ok(())
    }
}
