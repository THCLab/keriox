use serde::{de::DeserializeOwned, Serialize};
use sled::Tree;
use std::time::Duration;

use super::{tables::SledEventTreeVec, timestamped::Timestamped, DbError};

/// Collection of values, which removes values older than `duration`
///
pub struct Escrow<T> {
    tree: SledEventTreeVec<Timestamped<T>>,
    duration: Duration,
}

impl<'a, T: Serialize + DeserializeOwned + PartialEq + Clone> Escrow<T> {
    pub fn new(sled_tree: Tree, duration: Duration) -> Self {
        Self {
            tree: SledEventTreeVec::new(sled_tree),
            duration,
        }
    }

    pub fn add(&self, id: u64, event: T) -> Result<(), DbError> {
        let event = event.into();
        if !self.tree.contains_value(&event) {
            self.tree.push(id, event)
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

    pub fn get(&self, id: u64) -> Option<impl DoubleEndedIterator<Item = T>> {
        // TODO should return result?
        self.cleanup(id).ok();
        self.tree
            .iter_values(id)
            .map(|t| t.map(|t| t.signed_event_message))
    }

    pub fn remove(&self, id: u64, event: &T) -> Result<(), DbError> {
        self.tree.remove(id, &event.into())
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
