use crate::{error::Error, event::verifiable_event::VerifiableEvent};
use keri_core::prefix::IdentifierPrefix;
use std::path::Path;
pub mod escrow;
pub mod sled_db;

pub trait TelEventDatabase {
    fn new(path: impl AsRef<Path>) -> Result<Self, Error>
    where
        Self: Sized;

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error>;

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;

    fn add_new_management_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), Error>;

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>>;
}
