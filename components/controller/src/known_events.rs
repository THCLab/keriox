use std::path::PathBuf;
use keri_core::event_message::keri_version::KeriVersion;
use std::sync::Arc;

use keri_core::actor::parse_event_stream;
use keri_core::database::{EscrowCreator, EventDatabase};
use keri_core::error::Error;
use keri_core::event_message::signed_event_message::SignedNontransferableReceipt;
use keri_core::oobi::LocationScheme;
use keri_core::oobi_manager::storage::OobiStorageBackend;
use keri_core::prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix};

use keri_core::processor::escrow::partially_witnessed_escrow::PartiallyWitnessedEscrow;
use keri_core::processor::escrow::EscrowConfig;

use keri_core::processor::Processor;
use keri_core::state::IdentifierState;
use keri_core::{
    actor::{self, event_generator, prelude::SelfAddressingIdentifier},
    event::{event_data::EventData, sections::seal::Seal, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice, Op},
    },
    oobi::{Role, Scheme},
    oobi_manager::OobiManager,
    processor::{
        basic_processor::BasicProcessor, escrow::default_escrow_bus, event_storage::EventStorage,
    },
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};
use teliox::registry::RegistryStore;

use crate::error::ControllerError;
use crate::identifier::mechanics::MechanicsError;

#[derive(Debug, thiserror::Error)]
pub enum OobiRetrieveError {
    #[error("No oobi for {0} identifier")]
    MissingOobi(IdentifierPrefix, Option<Scheme>),
    #[error("Database error: {0}")]
    DbError(String),
}

impl From<keri_core::oobi::error::OobiError> for OobiRetrieveError {
    fn from(e: keri_core::oobi::error::OobiError) -> Self {
        OobiRetrieveError::DbError(e.to_string())
    }
}

pub struct KnownEvents<D, T, S>
where
    D: EventDatabase + EscrowCreator + 'static,
    T: RegistryStore + 'static,
    S: OobiStorageBackend,
{
    processor: BasicProcessor<D>,
    pub storage: Arc<EventStorage<D>>,
    pub oobi_manager: OobiManager<S>,
    pub partially_witnessed_escrow: Arc<PartiallyWitnessedEscrow<D>>,
    /// The registries this controller issues and the ones it accepted.
    pub registries: Arc<T>,
    /// The KERI version the controller writes its messages in.
    pub version: KeriVersion,
}

impl<D, T, S> KnownEvents<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn new(
        event_db: Arc<D>,
        oobi_storage: S,
        registries: Arc<T>,
        escrow_config: EscrowConfig,
    ) -> Result<Self, ControllerError> {
        let oobi_manager = OobiManager::with_storage(oobi_storage);
        let (notification_bus, escrow_set) =
            default_escrow_bus(event_db.clone(), escrow_config, None);
        let kel_storage = Arc::new(EventStorage::new(event_db.clone()));
        Ok(Self {
            processor: BasicProcessor::new(event_db.clone(), Some(notification_bus)),
            storage: kel_storage,
            oobi_manager,
            partially_witnessed_escrow: escrow_set.partially_witnessed,
            registries,
            version: KeriVersion::default(),
        })
    }

    /// Writes messages in `version` from now on.
    pub fn with_version(self, version: KeriVersion) -> Self {
        Self { version, ..self }
    }

    pub fn save(&self, message: &Message) -> Result<(), MechanicsError> {
        self.process(message)?;
        Ok(())
    }

    pub fn save_oobi(&self, oobi: &SignedReply) -> Result<(), MechanicsError> {
        Ok(self.oobi_manager.process_oobi(oobi)?)
    }

    pub fn current_public_keys(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .current
            .public_keys)
    }

    pub fn next_keys_hashes(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<SelfAddressingIdentifier>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .current
            .next_keys_data
            .next_keys_hashes())
    }

    pub fn get_watchers(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<IdentifierPrefix>, ControllerError> {
        Ok(self
            .oobi_manager
            .get_end_role(id, Role::Watcher)?
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                if let ReplyRoute::EndRoleAdd(adds) = r.reply.get_route() {
                    Some(adds.eid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: &Message) -> Result<Option<Vec<Message>>, Error> {
        let response = match msg.clone() {
            Message::Op(op) => match op {
                Op::Reply(rpy) => {
                    actor::process_reply(rpy, &self.oobi_manager, &self.processor, &self.storage)?;
                    None
                }
                Op::Query(_) => {
                    // TODO: Should controller respond to queries?
                    None
                }
                // Exchanges are delivered and handled through the mailbox.
                Op::Exchange(_) => {
                    return Err(Error::SemanticError(
                        "exchange messages are read from the mailbox, not processed here".into(),
                    ))
                }
            },
            Message::Notice(notice) => {
                self.processor.process_notice(&notice)?;
                None
            }
        };

        Ok(response)
    }

    /// Parse and process events stream
    pub fn process_stream(&self, stream: &[u8]) -> Result<(), ControllerError> {
        let messages = parse_event_stream(stream)?;
        for message in messages {
            self.process(&message)?;
        }
        Ok(())
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<LocationScheme>, OobiRetrieveError> {
        let location_schemas: Vec<_> = self
            .oobi_manager
            .get_loc_scheme(id)?
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Some(loc_scheme)
                } else {
                    None
                }
            })
            .collect();
        if location_schemas.is_empty() {
            Err(OobiRetrieveError::MissingOobi(id.clone(), None))
        } else {
            Ok(location_schemas)
        }
    }

    /// The location of `id` that can be reached over HTTP: the one `id`
    /// announced last, and the https one of two announced at the same time.
    ///
    /// The store keeps the latest reply per scheme, so an endpoint that
    /// moved from https to http (or to another host on another scheme)
    /// still has its old reply here. Preferring https regardless of age
    /// would keep sending to the address it left; the watcher picks the
    /// newest location for the same reason.
    pub fn find_http_location(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<LocationScheme, OobiRetrieveError> {
        self.oobi_manager
            .get_loc_scheme(id)?
            .into_iter()
            .filter_map(|reply| match reply.get_route() {
                ReplyRoute::LocScheme(loc)
                    if matches!(loc.scheme, Scheme::Http | Scheme::Https) =>
                {
                    Some((reply.get_timestamp(), loc.scheme == Scheme::Https, loc))
                }
                _ => None,
            })
            .max_by(|(a_dt, a_https, _), (b_dt, b_https, _)| {
                a_dt.cmp(b_dt).then(a_https.cmp(b_https))
            })
            .map(|(_, _, loc)| loc)
            .ok_or(OobiRetrieveError::MissingOobi(
                id.clone(),
                Some(Scheme::Http),
            ))
    }

    pub fn find_receipt(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        let rcts_from_db = self.storage.get_nt_receipts(id, sn)?;
        match &rcts_from_db {
            Some(rct) => {
                if rct.body.receipted_event_digest.eq(digest) {
                    Ok(rcts_from_db)
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    pub fn find_kel_with_receipts(&self, id: &IdentifierPrefix) -> Option<Vec<Notice>> {
        self.storage.get_kel_messages_with_receipts_all(id).unwrap()
    }

    pub fn find_kel(&self, id: &IdentifierPrefix) -> Option<String> {
        self.storage
            .get_kel(id)
            .unwrap()
            .map(|kel| String::from_utf8(kel).unwrap())
    }

    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        let witnesses = witnesses
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(MechanicsError::WrongWitnessPrefixError)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        event_generator::incept(
            public_keys,
            next_pub_keys,
            witnesses,
            witness_threshold,
            None,
            self.version,
        )
        .map_err(MechanicsError::generation)
    }

    /// Verifies event signature and adds it to kel.
    /// Returns new established identifier prefix.
    /// Meant to be used for identifiers with one key pair.
    /// Must call `IdentifierController::notify_witnesses` after calling this function.
    pub fn finalize_inception(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<IdentifierPrefix, MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.data.get_event_data() {
                    // TODO we assume here that provided signature matches 0th public key.
                    self.finalize_key_event(&ke, sig, 0)?;
                    Ok(ke.data.get_prefix())
                } else {
                    Err(MechanicsError::InceptionError(
                        "Wrong event type, should be inception event".into(),
                    ))
                }
            }
            _ => Err(MechanicsError::InceptionError(
                "Wrong event type, should be inception event".into(),
            )),
        }
    }

    /// Generate and return interaction event for given identifier data
    pub fn anchor_with_seal(
        &self,
        id: &IdentifierPrefix,
        payload: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, MechanicsError> {
        let state = self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?;
        event_generator::anchor_with_seal(
            state,
            payload,
            self.version,
        )
        .map_err(MechanicsError::generation)
    }

    pub fn get_current_witness_list(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .witness_config
            .witnesses)
    }

    /// Adds signature to event and processes it.
    /// Should call `IdentifierController::notify_witnesses` after calling this function.
    pub fn finalize_key_event(
        &self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
        own_index: usize,
    ) -> Result<(), MechanicsError> {
        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        // self.processor.process_own_event(signed_message)?;
        self.process(&Message::Notice(Notice::Event(signed_message)))?;

        Ok(())
    }

    pub fn get_state_at_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
    ) -> Result<IdentifierState, MechanicsError> {
        let identifier = event_message.data.get_prefix();
        Ok(match event_message.data.get_event_data() {
            EventData::Icp(_icp) => IdentifierState::default().apply(event_message)?,
            EventData::Rot(_rot) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?
                .apply(event_message)?,
            EventData::Ixn(_ixn) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?,
            EventData::Dip(_dip) => IdentifierState::default().apply(event_message)?,
            EventData::Drt(_drt) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?
                .apply(event_message)?,
        })
    }

    pub fn find_witnesses_at_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        let state = self.get_state_at_event(event_message)?;
        Ok(state.witness_config.witnesses)
    }

    pub fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(IdentifierPrefix, Vec<Message>), MechanicsError> {
        let mut messages_to_send = vec![];
        let (dest_prefix, role) = match &event.data.data {
            ReplyRoute::EndRoleAdd(role) => (role.eid.clone(), role.role.clone()),
            ReplyRoute::EndRoleCut(role) => (role.eid.clone(), role.role.clone()),
            _ => return Err(MechanicsError::EventFormatError),
        };
        let signed_reply = match signer_prefix {
            IdentifierPrefix::Basic(bp) => Message::Op(Op::Reply(SignedReply::new_nontrans(
                event,
                bp.clone(),
                sig[0].clone(),
            ))),
            _ => {
                let sigs = sig
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| IndexedSignature::new_both_same(sig, i as u16))
                    .collect();

                let signed_rpy = Message::Op(Op::Reply(SignedReply::new_trans(
                    event,
                    self.storage
                        .get_last_establishment_event_seal(signer_prefix)
                        .ok_or(MechanicsError::UnknownIdentifierError(
                            signer_prefix.clone(),
                        ))?,
                    sigs,
                )));
                if Role::Messagebox != role {
                    let kel = self
                        .storage
                        .get_kel_messages_with_receipts_all(signer_prefix)?
                        .ok_or(MechanicsError::UnknownIdentifierError(
                            signer_prefix.clone(),
                        ))?;

                    for ev in kel {
                        messages_to_send.push(Message::Notice(ev));
                    }
                };
                signed_rpy
            }
        };

        self.process(&signed_reply)?;

        messages_to_send.push(signed_reply.clone());

        Ok((dest_prefix, messages_to_send))
    }

    pub fn get_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState, MechanicsError> {
        self.storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))
    }
}

#[cfg(feature = "storage-redb")]
use keri_core::database::redb::RedbDatabase;
#[cfg(feature = "storage-redb")]
use keri_core::oobi_manager::storage::RedbOobiStorage;
#[cfg(feature = "storage-redb")]
use teliox::registry::store::redb::RedbRegistryStore;

#[cfg(feature = "storage-redb")]
pub type RedbKnownEvents = KnownEvents<RedbDatabase, RedbRegistryStore, RedbOobiStorage>;

#[cfg(feature = "storage-redb")]
impl RedbKnownEvents {
    pub fn with_redb(
        db_path: PathBuf,
        escrow_config: EscrowConfig,
    ) -> Result<Self, ControllerError> {
        let event_database = {
            let mut path = db_path.clone();
            path.push("events_database");
            Arc::new(
                RedbDatabase::new(&path)
                    .map_err(|e| ControllerError::DatabaseError(e.to_string()))?,
            )
        };
        let oobi_storage = RedbOobiStorage::new(event_database.raw_db())
            .map_err(|e| ControllerError::DatabaseError(e.to_string()))?;
        let registries = Arc::new(
            RedbRegistryStore::with_database(event_database.raw_db())
                .map_err(|e| ControllerError::DatabaseError(e.to_string()))?,
        );
        Self::new(event_database, oobi_storage, registries, escrow_config)
    }

    /// Fully in-memory event store (redb `InMemoryBackend` for the KEL, registries,
    /// OOBI and escrow databases). Nothing touches disk; all state lives
    /// exactly as long as this instance. Intended for tests, ephemeral
    /// agents and embedded use without filesystem access.
    pub fn new_in_memory(escrow_config: EscrowConfig) -> Result<Self, ControllerError> {
        let event_database = Arc::new(
            RedbDatabase::new_in_memory()
                .map_err(|e| ControllerError::DatabaseError(e.to_string()))?,
        );
        let oobi_storage = RedbOobiStorage::new(event_database.raw_db())
            .map_err(|e| ControllerError::DatabaseError(e.to_string()))?;
        let registries = Arc::new(
            RedbRegistryStore::with_database(event_database.raw_db())
                .map_err(|e| ControllerError::DatabaseError(e.to_string()))?,
        );
        Self::new(event_database, oobi_storage, registries, escrow_config)
    }
}

#[cfg(feature = "storage-postgres")]
use keri_core::database::postgres::oobi_storage::PostgresOobiStorage;
#[cfg(feature = "storage-postgres")]
use keri_core::database::postgres::PostgresDatabase;
#[cfg(feature = "storage-postgres")]
use teliox::registry::store::postgres::PostgresRegistryStore;

#[cfg(feature = "storage-postgres")]
pub type PostgresKnownEvents =
    KnownEvents<PostgresDatabase, PostgresRegistryStore, PostgresOobiStorage>;

#[cfg(feature = "storage-postgres")]
impl PostgresKnownEvents {
    pub async fn with_postgres(
        database_url: &str,
        escrow_config: EscrowConfig,
    ) -> Result<Self, ControllerError> {
        let event_db = Arc::new(
            PostgresDatabase::new(database_url)
                .await
                .map_err(|e| ControllerError::DatabaseError(e.to_string()))?,
        );
        event_db
            .run_migrations()
            .await
            .map_err(|e| ControllerError::DatabaseError(e.to_string()))?;
        let oobi_storage = PostgresOobiStorage::new(event_db.pool.clone());
        let registries = Arc::new(PostgresRegistryStore::new(event_db.pool.clone()));
        Self::new(event_db, oobi_storage, registries, escrow_config)
    }
}

#[cfg(test)]
mod tests {
    use keri_core::{
        actor::prelude::{HashFunctionCode, SerializationFormats},
        event_message::{
            keri_version::KeriVersion,
            msg::KeriEvent,
            timestamped::{TimeStamp, Timestamped},
        },
        oobi::{LocationScheme, Scheme},
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        processor::escrow::EscrowConfig,
        query::reply_event::{ReplyRoute, SignedReply},
        signer::Signer,
    };
    use url::Url;

    use super::RedbKnownEvents;

    /// A location reply `signer` signs for itself at `dt`.
    fn location(signer: &Signer, scheme: Scheme, url: &str, dt: &str) -> SignedReply {
        let prefix = BasicPrefix::Ed25519(signer.public_key());
        let eid = IdentifierPrefix::Basic(prefix.clone());
        let reply = KeriEvent::new(
            KeriVersion::V2_0,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            Timestamped {
                sender: Some(eid.clone()),
                timestamp: TimeStamp::parse_from_rfc3339(dt).unwrap(),
                data: ReplyRoute::LocScheme(LocationScheme::new(
                    eid,
                    scheme,
                    Url::parse(url).unwrap(),
                )),
            },
        );
        let signature = signer.sign(reply.encode().unwrap()).unwrap();
        SignedReply::new_nontrans(reply, prefix, SelfSigningPrefix::Ed25519Sha512(signature))
    }

    /// An endpoint that moved from https to http keeps its old https
    /// reply in the store: a reply for one scheme never replaces one for
    /// another. The location it named is gone, so preferring https because
    /// it is https sends every message to an address the endpoint left.
    #[test]
    fn a_newer_http_location_wins_over_a_stale_https_one() {
        let signer = Signer::new();
        let events = RedbKnownEvents::new_in_memory(EscrowConfig::default()).unwrap();
        let stale = location(
            &signer,
            Scheme::Https,
            "https://old-host/",
            "2026-06-10T15:40:42.607924+00:00",
        );
        let current = location(
            &signer,
            Scheme::Http,
            "http://new-host:3232/",
            "2026-11-03T11:50:39.033613+00:00",
        );
        events.save_oobi(&stale).unwrap();
        events.save_oobi(&current).unwrap();

        let eid = IdentifierPrefix::Basic(BasicPrefix::Ed25519(signer.public_key()));
        let found = events.find_http_location(&eid).unwrap();
        assert_eq!(found.scheme, Scheme::Http);
        assert_eq!(
            found.url,
            Some(Url::parse("http://new-host:3232/").unwrap())
        );
    }

    /// The other way round the newer https location is the one to use.
    #[test]
    fn a_newer_https_location_wins_over_a_stale_http_one() {
        let signer = Signer::new();
        let events = RedbKnownEvents::new_in_memory(EscrowConfig::default()).unwrap();
        events
            .save_oobi(&location(
                &signer,
                Scheme::Http,
                "http://old-host/",
                "2026-04-18T06:34:03.302837+00:00",
            ))
            .unwrap();
        events
            .save_oobi(&location(
                &signer,
                Scheme::Https,
                "https://new-host/",
                "2026-10-27T21:41:38.768801+00:00",
            ))
            .unwrap();

        let eid = IdentifierPrefix::Basic(BasicPrefix::Ed25519(signer.public_key()));
        let found = events.find_http_location(&eid).unwrap();
        assert_eq!(found.scheme, Scheme::Https);
    }
}
