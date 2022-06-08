use std::{convert::TryFrom, path::Path, sync::Arc};

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::{serialization_info::SerializationFormats, signed_event_message::Message},
    event_parsing::message::signed_event_stream,
    oobi::{OobiManager, Role},
    prefix::IdentifierPrefix,
    processor::{
        event_storage::EventStorage, notification::Notifier, validator::EventValidator, Processor,
    },
    query::{
        key_state_notice::KeyStateNotice,
        query_event::{QueryData, SignedQuery},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    state::IdentifierState,
};

pub fn parse_event_stream(stream: &[u8]) -> Result<Vec<Message>, Error> {
    let (_rest, events) =
        signed_event_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    events
        .into_iter()
        .map(|event_data| Message::try_from(event_data))
        .collect::<Result<_, _>>()
}
pub struct Component<P: Processor> {
    processor: P,
    pub storage: EventStorage,
    pub oobi_manager: Arc<OobiManager>,
}

impl<P: Processor> Component<P> {
    pub fn new(db: Arc<SledEventDatabase>, oobi_db_path: &Path) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let (processor, storage) = { (P::new(db.clone()), EventStorage::new(db.clone())) };

        Ok(Self {
            processor,
            storage,
            oobi_manager,
        })
    }

    pub fn register_observer(
        &mut self,
        observer: Arc<dyn Notifier + Send + Sync>,
    ) -> Result<(), Error> {
        self.processor.register_observer(observer)
    }

    pub fn save_oobi(&self, signed_oobi: SignedReply) -> Result<(), Error> {
        self.oobi_manager.save_oobi(signed_oobi)
    }

    pub fn get_db_ref(&self) -> Arc<SledEventDatabase> {
        self.storage.db.clone()
    }

    pub fn get_kel_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_kel(id)
    }

    pub fn get_receipts_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_escrowed_nt_receipts(id)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_end_role_for_id(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(self.oobi_manager.get_end_role(cid, role).unwrap())
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<ReplyEvent>>, Error> {
        Ok(self.oobi_manager.get_loc_scheme(eid)?)
    }

    pub fn get_ksn_for_prefix(&self, prefix: &IdentifierPrefix) -> Result<KeyStateNotice, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
        Ok(ksn)
    }

    /// Process for events that updates database
    pub fn process(&self, msg: Message) -> Result<(), Error> {
        match msg.clone() {
            Message::Reply(sr) => match sr.reply.get_route() {
                ReplyRoute::LocScheme(_)
                | ReplyRoute::EndRoleAdd(_)
                | ReplyRoute::EndRoleCut(_) => {
                    let validator = EventValidator::new(self.get_db_ref());
                    // check signature
                    validator.verify(&sr.reply.serialize()?, &sr.signature)?;
                    // check digest
                    sr.reply.check_digest()?;
                    // save
                    self.oobi_manager.process_oobi(sr)
                }
                ReplyRoute::Ksn(_, _) => self.processor.process(msg),
            },

            _ => self.processor.process(msg),
        }
    }

    pub fn process_signed_query(&self, qr: SignedQuery) -> Result<ReplyType, Error> {
        let signatures = qr.signatures;
        // check signatures
        let kc = self
            .storage
            .get_state(&qr.signer)?
            .ok_or_else(|| Error::SemanticError("No signer identifier in db".into()))?
            .current;

        if kc.verify(&qr.query.serialize()?, &signatures)? {
            // TODO check timestamps
            // unpack and check what's inside
            self.process_query(qr.query.get_query_data())
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    fn process_query(&self, qr: QueryData) -> Result<ReplyType, Error> {
        use crate::query::query_event::QueryRoute;

        match qr.route {
            QueryRoute::Log { args, .. } => Ok(ReplyType::Kel(
                self.storage
                    .get_kel_messages_with_receipts(&args.i)?
                    .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?,
            )),
            QueryRoute::Ksn { args, .. } => {
                let i = args.i;
                // return reply message with ksn inside
                let state = self
                    .storage
                    .get_state(&i)?
                    .ok_or_else(|| Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                Ok(ReplyType::Ksn(ksn))
            }
            QueryRoute::Mbx { args, .. } => {
                let mail = self.storage.get_mailbox_events(args)?;
                Ok(ReplyType::Mbx(mail))
            }
        }
    }
}
