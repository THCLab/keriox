use std::sync::Arc;

use keri_core::database::redb::RedbDatabase;
use keri_core::oobi_manager::storage::RedbOobiStorage;
use teliox::database::redb::RedbTelDatabase;

use crate::identifier::mechanics::cache::IdentifierCache;
use crate::{
    communication::Communication, config::ControllerConfig, error::ControllerError,
    identifier::Identifier, known_events::RedbKnownEvents,
};

use super::Controller;

pub type RedbController = Controller<RedbDatabase, RedbTelDatabase, RedbOobiStorage>;
pub type RedbIdentifier = Identifier<RedbDatabase, RedbTelDatabase, RedbOobiStorage>;

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
        let mut query_db_path = db_path.clone();
        query_db_path.push("query_cache");

        let events = Arc::new(RedbKnownEvents::with_redb(db_path, escrow_config)?);

        let query_cache = Arc::new(IdentifierCache::new(&query_db_path)?);
        let comm = Arc::new(Communication {
            events: events.clone(),
            transport,
            tel_transport,
        });

        let controller = Self {
            known_events: events.clone(),
            communication: comm,
            cache: query_cache,
        };
        if !initial_oobis.is_empty() {
            async_std::task::block_on(controller.setup_witnesses(&initial_oobis)).unwrap();
        }
        Ok(controller)
    }
}
