use serde::{de::DeserializeOwned, Serialize};
use sled::{Db, Tree};
use std::{path::Path, sync::Arc, time::Duration};

use crate::prefix::IdentifierPrefix;

use super::{
    tables::{SledEventTree, SledEventTreeVec},
    timestamped::Timestamped,
    DbError,
};

/// Collection of values, which removes values older than `duration`
///
pub struct Escrow<T> {
    escrow_db: Arc<EscrowDb>,
    tree: SledEventTreeVec<Timestamped<T>>,
    duration: Duration,
}

impl<'a, T: Serialize + DeserializeOwned + PartialEq + Clone> Escrow<T> {
    pub fn new<V>(name: V, duration: Duration, escrow_db: Arc<EscrowDb>) -> Self
    where
        V: AsRef<[u8]>,
    {
        Self {
            tree: SledEventTreeVec::new(escrow_db.add_bucket(name).unwrap()),
            duration,
            escrow_db,
        }
    }

    pub fn add(&self, id: &IdentifierPrefix, event: T) -> Result<(), DbError> {
        let event = event.into();
        if !self.tree.contains_value(&event) {
            self.tree.push(self.escrow_db.get_key(id)?, event)
        } else {
            Ok(())
        }
    }

    fn cleanup(&self, id: u64) -> Result<(), DbError> {
        match self.tree.iter_values(id) {
            Some(data) => {
                // Remove stale events
                let new_data = data.filter(|e| !e.is_stale(self.duration).unwrap());
                self.tree.put(id, new_data.collect())?;
            }
            None => (),
        };
        Ok(())
    }

    pub fn get(&self, id: &IdentifierPrefix) -> Option<impl DoubleEndedIterator<Item = T>> {
        // TODO should return result?
        let id_key = self.escrow_db.get_key(id).ok()?;
        self.cleanup(id_key).ok();
        self.tree
            .iter_values(id_key)
            .map(|t| t.map(|t| t.signed_event_message))
    }

    pub fn remove(&self, id: &IdentifierPrefix, event: &T) -> Result<(), DbError> {
        let id_key = self.escrow_db.get_key(id)?;
        self.tree.remove(id_key, &event.into())
    }

    pub fn get_all(&self) -> Option<impl DoubleEndedIterator<Item = T>> {
        // TODO should return result?
        let keys = self.tree.get_keys().unwrap();
        keys.for_each(|key| self.cleanup(key).unwrap());
        self.tree
            .get_all()
            .map(|t| t.map(|t| t.signed_event_message))
    }
}

pub struct EscrowDb {
    // "iids" tree
    // this thing is expensive, but everything else is cheeeeeep
    identifiers: SledEventTree<IdentifierPrefix>,
    db: Db,
}

impl EscrowDb {
    pub fn new<'a, P>(path: P) -> Result<Self, DbError>
    where
        P: Into<&'a Path>,
    {
        let db = sled::open(path.into())?;
        Ok(Self {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            db,
        })
    }

    pub fn add_bucket<V>(&self, name: V) -> Result<Tree, DbError>
    where
        V: AsRef<[u8]>,
    {
        Ok(self.db.open_tree(name)?)
    }

    pub fn get_key(&self, id: &IdentifierPrefix) -> Result<u64, DbError> {
        self.identifiers.designated_key(id)
    }
}
