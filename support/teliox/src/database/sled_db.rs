use crate::{database::TelEventDatabase, error::Error, event::verifiable_event::VerifiableEvent};
use keri_core::prefix::IdentifierPrefix;
use sled_tables::{
    self,
    tables::{SledEventTree, SledEventTreeVec},
};
use std::{path::Path, sync::Arc};

pub struct SledEventDatabase {
    db: Arc<sled::Db>,
    // "iids" tree
    identifiers: SledEventTree<IdentifierPrefix>,
    // "tels" tree
    tel_events: SledEventTreeVec<VerifiableEvent>,
    // "man" tree
    management_events: SledEventTreeVec<VerifiableEvent>,
}

impl TelEventDatabase for SledEventDatabase {
    fn new(path: impl AsRef<Path>) -> Result<Self, Error> {
        let db = Arc::new(sled::open(path)?);
        Ok(Self {
            db: db.clone(),
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            tel_events: SledEventTreeVec::new(db.open_tree(b"tels")?),
            management_events: SledEventTreeVec::new(db.open_tree(b"mans")?),
        })
    }

    fn add_new_event(&self, event: VerifiableEvent, id: &IdentifierPrefix) -> Result<(), Error> {
        self.tel_events
            .push(self.identifiers.designated_key(id), event)?;
        self.db.flush()?;
        Ok(())
    }

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.tel_events
            .iter_values(self.identifiers.designated_key(id))
    }

    fn add_new_management_event(
        &self,
        event: VerifiableEvent,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        self.management_events
            .push(self.identifiers.designated_key(id), event)?;
        self.db.flush()?;
        Ok(())
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.management_events
            .iter_values(self.identifiers.designated_key(id))
    }
}
