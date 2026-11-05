//! Consistent copies of open redb databases.
//!
//! A database a process holds open cannot be copied as a file on every
//! platform: on Windows redb locks the whole file range, so any other
//! handle's read fails (`ERROR_LOCK_VIOLATION`), and elsewhere a plain copy
//! can catch a write half done. [`copy_database`] instead reads every table
//! through the open handle inside one read transaction and writes it into a
//! fresh database file.
//!
//! redb opens tables only by their key and value types, so the copy knows
//! the types keriox stores. A table of any other type fails the copy rather
//! than being left out of it.

use std::path::{Path, PathBuf};

use redb::{
    Database, Key, MultimapTableDefinition, MultimapTableHandle, ReadTransaction,
    ReadableMultimapTable, ReadableTable, TableDefinition, TableError, TableHandle, Value,
    WriteTransaction,
};

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("database error: {0}")]
    Redb(Box<redb::Error>),
    #[error("table {0} has a key or value type the snapshot does not know")]
    UnknownTableType(String),
    #[error("snapshot destination {0} already exists")]
    DestinationExists(PathBuf),
    #[error("cannot create snapshot directory: {0}")]
    Io(#[from] std::io::Error),
}

impl From<redb::Error> for SnapshotError {
    fn from(e: redb::Error) -> Self {
        SnapshotError::Redb(Box::new(e))
    }
}

macro_rules! from_redb {
    ($($err:ty),*) => {$(
        impl From<$err> for SnapshotError {
            fn from(e: $err) -> Self {
                SnapshotError::Redb(Box::new(e.into()))
            }
        }
    )*};
}
from_redb!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// Write every table of `src`, as of one read transaction, into a new
/// database at `dest`. `dest` must not exist yet; its parent directories are
/// created.
pub fn copy_database(src: &Database, dest: &Path) -> Result<(), SnapshotError> {
    if dest.exists() {
        return Err(SnapshotError::DestinationExists(dest.to_path_buf()));
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let read = src.begin_read()?;
    let copy = Database::create(dest)?;
    let write = copy.begin_write()?;
    for table in read.list_tables()? {
        copy_table(&read, &write, table.name())?;
    }
    for table in read.list_multimap_tables()? {
        copy_multimap_table(&read, &write, table.name())?;
    }
    write.commit()?;
    Ok(())
}

/// Try each `(key, value)` type keriox stores until one opens the table.
macro_rules! copy_as {
    ($copy:ident, $read:expr, $write:expr, $name:expr, $(($k:ty, $v:ty)),* $(,)?) => {{
        $(
            match $copy::<$k, $v>($read, $write, $name) {
                Err(TableError::TableTypeMismatch { .. }) => {}
                other => return other.map_err(SnapshotError::from),
            }
        )*
        Err(SnapshotError::UnknownTableType($name.to_string()))
    }};
}

fn copy_table(
    read: &ReadTransaction,
    write: &WriteTransaction,
    name: &str,
) -> Result<(), SnapshotError> {
    copy_as!(
        copy_typed_table,
        read,
        write,
        name,
        (&'static [u8], &'static [u8]),
        (&'static [u8], u64),
        (&'static str, &'static [u8]),
        (&'static str, &'static str),
        (&'static str, u64),
        ((&'static str, u64), &'static [u8]),
        ((&'static str, &'static str), &'static [u8]),
        ((&'static str, &'static str), &'static str),
        ((&'static str, u64, &'static str), &'static [u8]),
    )
}

fn copy_multimap_table(
    read: &ReadTransaction,
    write: &WriteTransaction,
    name: &str,
) -> Result<(), SnapshotError> {
    copy_as!(
        copy_typed_multimap_table,
        read,
        write,
        name,
        (&'static [u8], &'static [u8]),
        ((&'static str, u64), &'static [u8]),
        ((&'static [u8], &'static [u8]), &'static [u8]),
    )
}

fn copy_typed_table<K: Key + 'static, V: Value + 'static>(
    read: &ReadTransaction,
    write: &WriteTransaction,
    name: &str,
) -> Result<(), TableError> {
    let definition = TableDefinition::<K, V>::new(name);
    let source = read.open_table(definition)?;
    let mut target = write.open_table(definition)?;
    for entry in source.iter()? {
        let (key, value) = entry?;
        target.insert(key.value(), value.value())?;
    }
    Ok(())
}

fn copy_typed_multimap_table<K: Key + 'static, V: Key + 'static>(
    read: &ReadTransaction,
    write: &WriteTransaction,
    name: &str,
) -> Result<(), TableError> {
    let definition = MultimapTableDefinition::<K, V>::new(name);
    let source = read.open_multimap_table(definition)?;
    let mut target = write.open_multimap_table(definition)?;
    for entry in source.iter()? {
        let (key, values) = entry?;
        for value in values {
            target.insert(key.value(), value?.value())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableTableMetadata;

    const BYTES: TableDefinition<&[u8], &[u8]> = TableDefinition::new("bytes");
    const KEL: TableDefinition<(&str, u64), &[u8]> = TableDefinition::new("kel");
    const SIGS: MultimapTableDefinition<&[u8], &[u8]> = MultimapTableDefinition::new("sigs");
    const UNKNOWN: TableDefinition<u32, u32> = TableDefinition::new("unknown");

    #[test]
    fn copies_every_table_and_value() {
        let dir = tempfile::tempdir().unwrap();
        let src = Database::create(dir.path().join("src")).unwrap();
        let write = src.begin_write().unwrap();
        {
            let mut bytes = write.open_table(BYTES).unwrap();
            bytes.insert(b"a".as_slice(), b"1".as_slice()).unwrap();
            let mut kel = write.open_table(KEL).unwrap();
            kel.insert(("E1", 0), b"icp".as_slice()).unwrap();
            kel.insert(("E1", 1), b"rot".as_slice()).unwrap();
            let mut sigs = write.open_multimap_table(SIGS).unwrap();
            sigs.insert(b"d".as_slice(), b"s1".as_slice()).unwrap();
            sigs.insert(b"d".as_slice(), b"s2".as_slice()).unwrap();
        }
        write.commit().unwrap();

        let dest = dir.path().join("nested").join("copy");
        copy_database(&src, &dest).unwrap();
        drop(src);

        let copy = Database::create(&dest).unwrap();
        let read = copy.begin_read().unwrap();
        let bytes = read.open_table(BYTES).unwrap();
        assert_eq!(bytes.get(b"a".as_slice()).unwrap().unwrap().value(), b"1");
        let kel = read.open_table(KEL).unwrap();
        assert_eq!(kel.len().unwrap(), 2);
        assert_eq!(kel.get(("E1", 1)).unwrap().unwrap().value(), b"rot");
        let sigs = read.open_multimap_table(SIGS).unwrap();
        let values: Vec<Vec<u8>> = sigs
            .get(b"d".as_slice())
            .unwrap()
            .map(|v| v.unwrap().value().to_vec())
            .collect();
        assert_eq!(values, vec![b"s1".to_vec(), b"s2".to_vec()]);
    }

    #[test]
    fn refuses_a_table_of_an_unknown_type() {
        let dir = tempfile::tempdir().unwrap();
        let src = Database::create(dir.path().join("src")).unwrap();
        let write = src.begin_write().unwrap();
        write.open_table(UNKNOWN).unwrap().insert(1, 2).unwrap();
        write.commit().unwrap();

        let err = copy_database(&src, &dir.path().join("copy")).unwrap_err();
        assert!(matches!(err, SnapshotError::UnknownTableType(name) if name == "unknown"));
    }

    #[test]
    fn refuses_an_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let src = Database::create(dir.path().join("src")).unwrap();
        let dest = dir.path().join("copy");
        std::fs::write(&dest, b"").unwrap();

        let err = copy_database(&src, &dest).unwrap_err();
        assert!(matches!(err, SnapshotError::DestinationExists(_)));
    }
}
