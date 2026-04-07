use std::sync::Arc;

use keri_core::database::postgres::PostgresDatabase;
use keri_core::database::postgres::oobi_storage::PostgresOobiStorage;
use teliox::database::postgres::PostgresTelDatabase;

#[cfg(feature = "query_cache")]
use crate::identifier::mechanics::cache::IdentifierCache;
use crate::{
    communication::Communication,
    config::ControllerConfig,
    error::ControllerError,
    identifier::Identifier,
    known_events::PostgresKnownEvents,
};

use super::Controller;

pub type PostgresController = Controller<PostgresDatabase, PostgresTelDatabase, PostgresOobiStorage>;
pub type PostgresIdentifier = Identifier<PostgresDatabase, PostgresTelDatabase, PostgresOobiStorage>;

impl PostgresController {
    pub async fn new_postgres(
        database_url: &str,
        config: ControllerConfig,
    ) -> Result<Self, ControllerError> {
        let ControllerConfig {
            db_path: _db_path,
            initial_oobis,
            escrow_config,
            transport,
            tel_transport,
        } = config;

        #[cfg(feature = "query_cache")]
        let mut query_db_path = _db_path.clone();
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
