#![allow(dead_code)]
use std::{convert::TryInto, marker::PhantomData};

use arrayref::array_ref;
use serde::{de::DeserializeOwned, Serialize};

use super::sled::DbError;

/// Imitates collection table per key
///
pub(crate) struct SledEventTreeVec<T> {
    tree: sled::Tree,
    marker: PhantomData<T>,
}

impl<T> SledEventTreeVec<T> {
    /// table constructor
    ///
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }
}

/// DB "Tables" functionality
///
impl<T> SledEventTreeVec<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Gets all elements for given `key` as Vec<T>
    ///
    pub fn get(&self, key: u64) -> Result<Option<Vec<T>>, DbError> {
        if let Some(v) = self.tree.get(key_bytes(key))? {
            let set: Vec<T> = serde_cbor::from_slice(&v)?;
            Ok(Some(set))
        } else {
            Ok(None)
        }
    }

    /// Overwrites or adds new key<->value into the tree
    ///
    pub fn put(&self, key: u64, value: Vec<T>) -> Result<(), DbError> {
        self.tree
            .insert(key_bytes(key), serde_cbor::to_vec(&value)?)?;
        Ok(())
    }

    /// Pushes element to existing set of T
    /// or creates new one with single element
    ///
    pub fn push(&self, key: u64, value: T) -> Result<(), DbError> {
        if let Ok(Some(mut set)) = self.get(key) {
            set.push(value);
            self.put(key, set)
        } else {
            self.put(key, vec![value])
        }
    }

    /// Removes value `T` if present
    ///
    pub fn remove(&self, key: u64, value: &T) -> Result<(), DbError>
    where
        T: PartialEq,
    {
        if let Ok(Some(set)) = self.get(key) {
            self.put(key, set.into_iter().filter(|e| e != value).collect())
        } else {
            Ok(())
        }
    }

    /// Appends one `Vec<T>` into DB present one
    /// or `put()`s it if not present as is.
    ///
    pub fn append(&self, key: u64, value: Vec<T>) -> Result<(), DbError>
    where
        T: ToOwned + Clone,
    {
        if let Ok(Some(mut set)) = self.get(key) {
            set.append(&mut value.to_owned());
            Ok(())
        } else {
            self.put(key, value)
        }
    }

    /// check if `T` is present in `Vec<T>` in the DB
    ///
    pub fn contains_value(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.tree.iter().flatten().any(|(_k, v)| {
            serde_cbor::from_slice::<Vec<T>>(&v)
                .unwrap()
                .contains(value)
        })
    }

    /// iterate inner collection under same key
    ///
    pub fn iter_values(&self, key: u64) -> Option<impl DoubleEndedIterator<Item = T>> {
        if let Ok(Some(values)) = self.tree.get(key_bytes(key)) {
            Some(
                serde_cbor::from_slice::<Vec<T>>(&values)
                    .unwrap()
                    .into_iter(),
            )
        } else {
            None
        }
    }

    pub fn get_all(&self) -> Option<impl DoubleEndedIterator<Item = T>> {
        Some(
            self.tree
                .into_iter()
                .values()
                .flat_map(|values| serde_cbor::from_slice::<Vec<T>>(&values.unwrap()).unwrap()),
        )
    }

    pub fn get_keys(&self) -> Option<impl DoubleEndedIterator<Item = u64>> {
        Some(
            self.tree
                .into_iter()
                .keys()
                .map(|keys| u64::from_be_bytes(keys.unwrap().to_vec().try_into().unwrap())),
        )
    }
}

/// Direct singular key-value of T table
///
pub(crate) struct SledEventTree<T> {
    tree: sled::Tree,
    marker: PhantomData<T>,
}

impl<T> SledEventTree<T> {
    /// table constructor
    ///
    pub fn new(tree: sled::Tree) -> Self {
        Self {
            tree,
            marker: PhantomData,
        }
    }
}

/// DB "Tables" functionality
///
impl<T> SledEventTree<T>
where
    T: Serialize + DeserializeOwned,
{
    /// get entire Vec<T> in one go
    ///
    pub fn get(&self, id: u64) -> Result<Option<T>, DbError> {
        match self.tree.get(key_bytes(id))? {
            Some(value) => Ok(Some(serde_cbor::from_slice(&value)?)),
            None => Ok(None),
        }
    }

    /// check if provided `u64` key is present in the db
    ///
    pub fn contains_key(&self, id: u64) -> Result<bool, DbError> {
        Ok(self.tree.contains_key(key_bytes(id))?)
    }

    /// check if value `T` is present in the db
    ///
    pub fn contains_value(&self, value: &T) -> bool
    where
        T: PartialEq,
    {
        self.tree
            .iter()
            .flatten()
            .any(|(_, v)| serde_cbor::from_slice::<T>(&v).unwrap().eq(value))
    }

    /// insert `T` with given `key`
    /// Warning! This will rewrite existing value with the same `key`
    ///
    pub fn insert(&self, key: u64, value: &T) -> Result<(), DbError> {
        self.tree
            .insert(key_bytes(key), serde_cbor::to_vec(value)?)?;
        Ok(())
    }

    /// iterator over `T` deserialized from the db
    ///
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = T> {
        self.tree
            .iter()
            .flatten()
            .flat_map(|(_, v)| serde_cbor::from_slice(&v))
    }

    /// provides which `u64` key to use to add NEW entry
    ///
    pub fn get_next_key(&self) -> u64 {
        if let Ok(Some((k, _v))) = self.tree.last() {
            u64::from_be_bytes(array_ref!(k, 0, 8).to_owned()) + 1
        } else {
            0
        }
    }

    /// somewhat expensive! gets optional `u64` key for given `&T`
    /// if present in the db
    ///
    pub fn get_key_by_value(&self, value: &T) -> Result<Option<u64>, DbError>
    where
        T: Serialize,
    {
        let value = serde_cbor::to_vec(value)?;
        if let Some((key, _)) = self.tree.iter().flatten().find(|(_k, v)| v.eq(&value)) {
            Ok(Some(u64::from_be_bytes(array_ref!(key, 0, 8).to_owned())))
        } else {
            Ok(None)
        }
    }

    /// Returns key for value or inserts new one if not present.
    /// combination of `get_key_by_value()` and `get_next_key()`
    /// also expensive...
    /// to be used when unsure if identifier is present in the db
    ///
    pub fn designated_key(&self, identifier: &T) -> Result<u64, DbError>
    where
        T: Serialize,
    {
        if let Ok(Some(key)) = self.get_key_by_value(identifier) {
            Ok(key)
        } else {
            let key = self.get_next_key();
            self.tree
                .insert(key_bytes(key), serde_cbor::to_vec(identifier)?)?;
            Ok(key)
        }
    }
}

fn key_bytes(key: u64) -> [u8; 8] {
    key.to_be_bytes()
}
