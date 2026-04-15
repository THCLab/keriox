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

use crate::identifier::mechanics::cache::IdentifierCache;
use crate::{
    communication::Communication,
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
mod redb;
#[cfg(feature = "storage-redb")]
pub use redb::{RedbController, RedbIdentifier};

#[cfg(feature = "storage-postgres")]
mod postgres;
#[cfg(feature = "storage-postgres")]
pub use postgres::{PostgresController, PostgresIdentifier};
