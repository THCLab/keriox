use std::sync::Arc;

use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event_message::signature::Signature,
    oobi::LocationScheme,
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::validator::VerificationError,
    state::IdentifierState,
};
use teliox::database::TelEventDatabase;

#[cfg(feature = "query_cache")]
use crate::identifier::mechanics::cache::IdentifierCache;
use crate::{
    communication::Communication,
    config::ControllerConfig,
    error::ControllerError,
    identifier::{mechanics::MechanicsError, Identifier},
    known_events::KnownEvents,
};
pub mod verifying;

pub struct Controller<D, T, S>
where
    D: EventDatabase + EscrowCreator + 'static,
    T: TelEventDatabase + 'static,
    S: OobiStorageBackend,
{
    pub known_events: Arc<KnownEvents<D, T, S>>,
    pub communication: Arc<Communication<D, T, S>>,
    #[cfg(feature = "query_cache")]
    pub cache: Arc<IdentifierCache>,
}

impl<D, T, S> Controller<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub async fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        self.setup_witnesses(&witnesses).await?;
        self.known_events
            .incept(public_keys, next_pub_keys, witnesses, witness_threshold)
    }

    pub fn finalize_incept(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<Identifier<D, T, S>, ControllerError> {
        let initialized_id = self.known_events.finalize_inception(event, sig).unwrap();
        Ok(Identifier::new(
            initialized_id,
            None,
            self.known_events.clone(),
            self.communication.clone(),
            #[cfg(feature = "query_cache")]
            self.cache.clone(),
        ))
    }

    async fn setup_witnesses(&self, oobis: &[LocationScheme]) -> Result<(), MechanicsError> {
        for lc in oobis {
            self.communication.resolve_loc_schema(lc).await?;
        }
        Ok(())
    }

    pub fn get_kel_with_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<Vec<keri_core::event_message::signed_event_message::Notice>> {
        self.known_events.find_kel_with_receipts(id)
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), VerificationError> {
        self.known_events.verify(data, signature)
    }

    pub fn find_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState, MechanicsError> {
        self.known_events.get_state(id)
    }
}

#[cfg(feature = "storage-redb")]
use crate::known_events::RedbKnownEvents;
#[cfg(feature = "storage-redb")]
use keri_core::database::redb::RedbDatabase;
#[cfg(feature = "storage-redb")]
use keri_core::oobi_manager::storage::RedbOobiStorage;
#[cfg(feature = "storage-redb")]
use teliox::database::redb::RedbTelDatabase;

#[cfg(feature = "storage-postgres")]
use crate::known_events::PostgresKnownEvents;
#[cfg(feature = "storage-postgres")]
use keri_core::database::postgres::PostgresDatabase;
#[cfg(feature = "storage-postgres")]
use keri_core::database::postgres::oobi_storage::PostgresOobiStorage;
#[cfg(feature = "storage-postgres")]
use teliox::database::postgres::PostgresTelDatabase;

#[cfg(feature = "storage-redb")]
pub type RedbController = Controller<RedbDatabase, RedbTelDatabase, RedbOobiStorage>;

#[cfg(feature = "storage-postgres")]
pub type PostgresController = Controller<PostgresDatabase, PostgresTelDatabase, PostgresOobiStorage>;

#[cfg(feature = "storage-redb")]
impl RedbController {
    pub fn new(config: ControllerConfig) -> Result<Self, ControllerError> {
        let ControllerConfig {
            db_path,
            initial_oobis,
            escrow_config,
            transport,
            tel_transport,
        } = config;
        std::fs::create_dir_all(&db_path).unwrap();
        #[cfg(feature = "query_cache")]
        let mut query_db_path = db_path.clone();
        #[cfg(feature = "query_cache")]
        query_db_path.push("query_cache");

        let events = Arc::new(RedbKnownEvents::with_redb(db_path, escrow_config)?);

        #[cfg(feature = "query_cache")]
        let query_cache = Arc::new(IdentifierCache::new(&query_db_path)?);
        let comm = Arc::new(Communication {
            events: events.clone(),
            transport,
            tel_transport,
        });

        let controller = Self {
            known_events: events.clone(),
            communication: comm,
            #[cfg(feature = "query_cache")]
            cache: query_cache,
        };
        if !initial_oobis.is_empty() {
            async_std::task::block_on(controller.setup_witnesses(&initial_oobis)).unwrap();
        }
        Ok(controller)
    }
}

#[cfg(feature = "storage-postgres")]
impl PostgresController {
    pub async fn new_postgres(
        database_url: &str,
        config: ControllerConfig,
    ) -> Result<Self, ControllerError> {
        let ControllerConfig {
            db_path,
            initial_oobis,
            escrow_config,
            transport,
            tel_transport,
        } = config;

        #[cfg(feature = "query_cache")]
        let mut query_db_path = db_path.clone();
        #[cfg(feature = "query_cache")]
        query_db_path.push("query_cache");

        let events = Arc::new(
            PostgresKnownEvents::with_postgres(database_url, escrow_config).await?,
        );

        #[cfg(feature = "query_cache")]
        let query_cache = Arc::new(IdentifierCache::new(&query_db_path)?);

        let comm = Arc::new(Communication {
            events: events.clone(),
            transport,
            tel_transport,
        });

        let controller = Self {
            known_events: events.clone(),
            communication: comm,
            #[cfg(feature = "query_cache")]
            cache: query_cache,
        };
        if !initial_oobis.is_empty() {
            controller.setup_witnesses(&initial_oobis).await.unwrap();
        }
        Ok(controller)
    }
}
