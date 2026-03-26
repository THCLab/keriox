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
            _ => todo!(),
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
            _ => todo!(),
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
    use crate::{
        actor::prelude::{BasicProcessor, Message},
        database::redb::RedbDatabase,
        error::Error,
        event_message::signed_event_message::Op,
        prefix::IdentifierPrefix,
        processor::{escrow::reply_escrow::ReplyEscrow, notification::JustNotification, Processor},
    };
    use cesrox::{parse, parse_many};
    use std::{fs, sync::Arc};
    use tempfile::{Builder, NamedTempFile};

    #[test]
    pub fn test_reply_escrow() -> Result<(), Error> {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let mut event_processor = BasicProcessor::new(events_db.clone(), None);
        let rpy_escrow = Arc::new(ReplyEscrow::new(events_db.clone()));
        event_processor.register_observer(
            rpy_escrow.clone(),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::KsnOutOfOrder,
            ],
        )?;

        let identifier: IdentifierPrefix =
            "EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH".parse()?;

        let kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAArkDBeflIAo4kBsKnc754XHJvdLnf04iq-noTFEJkbv2MeIGZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0-nlhHEE-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EHZks1BQ_ieuzASY7VoZNIOgIfnlE-SZJzO3OP_Wf3zM","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","kt":"1","k":["DMm-PHnlVVw-yQGqxxQFH3ynIGBrwkOCll9NJsszS4M1"],"nt":"1","n":["EGDpG5Ca3-vx-0O_rCXo44CG9VfjvDM8kXZlXt5TRGqq"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAB49lUrFy86023zwry5pLz3_stNBPLU2Zoj2HO02W-J-fXvA9EL7BOpuVjEdhPHz1KbRWOKljI8yY3PZR3PyiMG-EAB0AAAAAAAAAAAAAAAAAAAAAAB1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"2","p":"EHZks1BQ_ieuzASY7VoZNIOgIfnlE-SZJzO3OP_Wf3zM","kt":"1","k":["DMjdd0iohdRbFaFUeQuK_9eSSS1AcQVwZpJXg-QGFqZX"],"nt":"1","n":["ECDBhT8ht1Z2WFeC6C_7sCAPkduj3DDjEz2cxI_RSo-I"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAtK2_idK0_YfBrswOvbjBFWtjTZ5XRRU42HC7eoph_gi67BCeTaMBUBKyx5LZYnAG3GzOl5Xj-CXkvzSlwJ10K-EAB0AAAAAAAAAAAAAAAAAAAAAAC1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"3","p":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","kt":"1","k":["DK3AM_4Jg07liB5_5jkA3kiv2iSEYsOSDMzw-4oMxA29"],"nt":"1","n":["EGdk-oXzuVUatJYeIuai9wlUJ0ulVUTrb9w0LPPuuyB0"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAMxebsLh1V2NIHJl0diSC242MSg5TNSbtgjZPuf34adjV9rs6B73pWyt-TmRWMIY-me9-pg3eN0p4wQsyBWIEC-EAB0AAAAAAAAAAAAAAAAAAAAAAD1AAG2021-01-01T00c00c00d000000p00c00"#;

        let parsed = parse_many(kel.as_bytes()).unwrap().1;
        let kel_events = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

        let rest_of_kel = r#"{"v":"KERI10JSON000160_","t":"rot","d":"EHVjHgDO5Gm7VJX1_0pfajNdsr5yMWxeu8jTBDFM3Hxx","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"4","p":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","kt":"1","k":["DHCf_d5wepRUYrkwii7D9D_ix9m8YJ1u6c7Kf4vChB2-"],"nt":"1","n":["EDnPDsp4HhTExdfBa_ZKoW9wwVsO8SXQnDAikGP2wbcX"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAp185sbBdPawKcVHO_8mrMIYtAG5mKNlQWWvCIFVlIszQcge3FAEfYq4cw9Gh_tY82PBPLBPlgXYjLYnRxXQkD-EAB0AAAAAAAAAAAAAAAAAAAAAAE1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EFltRrVgHygpUoAIpyiYHUe0Zt8-lPQ20iNk2fA0CGnB","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"5","p":"EHVjHgDO5Gm7VJX1_0pfajNdsr5yMWxeu8jTBDFM3Hxx","kt":"1","k":["DMOFqHNTbaOrzXv6Hs6d08Nd_mLo7wiH-888vFGtFWmV"],"nt":"1","n":["ECYVu54u3AXOkOZjf2RZnbeRxbu10vBW85rZTgXKcoVH"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAERG7cm3_SLovALeBeadaIzCh55ul_Mj3mp4UNdzvmdbBbGMDTxrkEVHpM25BOROuhIRKWUdw6yVFubbKgl7wI-EAB0AAAAAAAAAAAAAAAAAAAAAAF1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EGs1eJFrFrcenQouDUk57AA5lYs8E-xOVcLPu0me-gyS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"6","p":"EFltRrVgHygpUoAIpyiYHUe0Zt8-lPQ20iNk2fA0CGnB","kt":"1","k":["DIxsQo0QFWhYlX34UHDw39OG4nIr5tky9S5Jwi97o7-d"],"nt":"1","n":["EJyVykl3kJen1vWe9MkOKNQ6DN6h16hAcqU7h77MSkpn"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAADkk6omMn4qARRuu6EJlSqvkEcZlSRxF9wDMuJLf31k0U7XBgFaYMJA50V7yUI46GGbF7t3x72NZxiM0EhzeqMB-EAB0AAAAAAAAAAAAAAAAAAAAAAG1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"7","p":"EGs1eJFrFrcenQouDUk57AA5lYs8E-xOVcLPu0me-gyS","kt":"1","k":["DME53BRS5KnXzsfYqT8I2DCfl6nMOrlYBN_Fm3wIh9M0"],"nt":"1","n":["EKsCb2J8R1gnygI5QiYIJ67CJYrXx-uZ_iM0yITQYDV9"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAB6IYTjz7nE_44ttVWLyNsIxjMOUs8mx1_L-XiD1Hu61W8efpvlf2cpZWrhmFuNtAxGTyFpfXL9dwjaC0cQTsUH-EAB0AAAAAAAAAAAAAAAAAAAAAAH1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"8","p":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","kt":"1","k":["DDnnUcnyEHuGfhjUpW4APLcSCsseC4trSdUtGIcu5dk_"],"nt":"1","n":["EEH-Nd5uWnAjXzX1mwBsz6WZWbCbGZBZIuurBl2r8TPn"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAC5QaZ2nCtxB9-RQ68LxbKABJ_QP7aFbAVnAPW4usBCiNbTL6DDzSI1Z3ykh6RPczk0HYfRW39kbtMWsIPHQ1MJ-EAB0AAAAAAAAAAAAAAAAAAAAAAI1AAG2021-01-01T00c00c00d000000p00c00"#;
        let parsed = parse_many(rest_of_kel.as_bytes()).unwrap().1;
        let rest_of_kel = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

        let old_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EJjB0S6SaAA1ymaO0cXVmv5kJagHVVUVpxD6q5_jrcgP","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":{"v":"KERI10JSON0001e2_","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"3","p":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DK3AM_4Jg07liB5_5jkA3kiv2iSEYsOSDMzw-4oMxA29"],"nt":"1","n":["EGdk-oXzuVUatJYeIuai9wlUJ0ulVUTrb9w0LPPuuyB0"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","br":[],"ba":[]},"di":""}}-VA0-FABEA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH0AAAAAAAAAAAAAAAAAAAAAADEHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs-AABAADfyYgxdTg4vvKcbCHaog79P3KVJJX_bYMZOuOobmLM9uWLmTVHFvFB36-hS062DfCsCyBF0tmODSlmVY-TksUC"#;
        let parsed = parse(old_rpy.as_bytes()).unwrap().1;
        let deserialized_old_rpy = Message::try_from(parsed).unwrap();

        let new_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EJX7EebLoW8VTVvO3iPuFGzy38BU6OEEsRR9nFjzgeL6","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":{"v":"KERI10JSON0001e2_","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"8","p":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","f":"8","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DDnnUcnyEHuGfhjUpW4APLcSCsseC4trSdUtGIcu5dk_"],"nt":"1","n":["EEH-Nd5uWnAjXzX1mwBsz6WZWbCbGZBZIuurBl2r8TPn"],"bt":"0","b":[],"c":[],"ee":{"s":"8","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","br":[],"ba":[]},"di":""}}-VA0-FABEA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH0AAAAAAAAAAAAAAAAAAAAAAIEJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7-AABAABuq6TXP5ZHc62y8NxNnKJjyJ1b4Nc1Mfu4ZKzg_47kbRyBriC9k7vnuidpIOfjUE7tnseaY5p6Gyr5qULXJWEK"#;
        let parsed = parse(new_rpy.as_bytes()).unwrap().1;
        let deserialized_new_rpy = Message::try_from(parsed).unwrap();

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
