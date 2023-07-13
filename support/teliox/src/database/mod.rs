use crate::{error::Error, event::verifiable_event::VerifiableEvent};
use keri::prefix::IdentifierPrefix;
use sled_tables::{
    self,
    tables::{SledEventTree, SledEventTreeVec},
};
use std::path::Path;

pub struct EventDatabase {
    // "iids" tree
    identifiers: SledEventTree<IdentifierPrefix>,
    // "tels" tree
    tel_events: SledEventTreeVec<VerifiableEvent>,
    // "man" tree
    management_events: SledEventTreeVec<VerifiableEvent>,
}

impl EventDatabase {
    pub fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = sled::open(path)?;
        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            tel_events: SledEventTreeVec::new(db.open_tree(b"tels")?),
            management_events: SledEventTreeVec::new(db.open_tree(b"mans")?),
        })
    }

    pub fn add_new_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        Ok(self
            .tel_events
            .push(self.identifiers.designated_key(id), event)?)
    }

    pub fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.tel_events
            .iter_values(self.identifiers.designated_key(id))
    }

    pub fn add_new_management_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        Ok(self
            .management_events
            .push(self.identifiers.designated_key(id), event)?)
    }

    pub fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.management_events
            .iter_values(self.identifiers.designated_key(id))
    }
}
