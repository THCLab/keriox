use std::sync::Arc;

use said::SelfAddressingIdentifier;
use sqlx::{PgPool, Row};

use crate::{
    database::{
        postgres::{
            error::PostgresError, loging::PostgresWriteTxnMode, PostgresDatabase,
            PostgresLogDatabase,
        },
        rkyv_adapter::{self, serialize_said},
        EscrowCreator, EscrowDatabase, LogDatabase as _, SequencedEventDatabase,
    },
    event::KeyEvent,
    event_message::{msg::KeriEvent, signed_event_message::SignedEventMessage},
    prefix::IdentifierPrefix,
};

impl EscrowCreator for PostgresDatabase {
    type EscrowDatabaseType = PostgresSnKeyEscrow;

    fn create_escrow_db(&self, table_name: &'static str) -> Self::EscrowDatabaseType {
        PostgresSnKeyEscrow::new(
            Arc::new(PostgresSnKeyDatabase::new(self.pool.clone(), table_name)),
            self.log_db.clone(),
        )
    }
}

pub struct PostgresSnKeyEscrow {
    escrow: Arc<
        dyn SequencedEventDatabase<
            DatabaseType = PgPool,
            Error = PostgresError,
            DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>,
        >,
    >,
    log: Arc<PostgresLogDatabase>,
}

impl EscrowDatabase for PostgresSnKeyEscrow {
    type EscrowDatabaseType = PgPool;

    type LogDatabaseType = PostgresLogDatabase;

    type Error = PostgresError;

    type EventIter = Box<dyn Iterator<Item = SignedEventMessage> + Send>;

    fn new(
        escrow: Arc<
            dyn SequencedEventDatabase<
                DatabaseType = Self::EscrowDatabaseType,
                Error = Self::Error,
                DigestIter = Box<dyn Iterator<Item = said::SelfAddressingIdentifier>>,
            >,
        >,
        log: Arc<Self::LogDatabaseType>,
    ) -> Self
    where
        Self: Sized,
    {
        Self { escrow, log }
    }

    fn save_digest(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event_digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        self.escrow.insert(id, sn, event_digest)
    }

    fn insert(&self, event: &SignedEventMessage) -> Result<(), Self::Error> {
        self.log
            .log_event(&PostgresWriteTxnMode::CreateNew, event)?;
        let said = event.event_message.digest().unwrap();
        let id = event.event_message.data.get_prefix();
        let sn = event.event_message.data.sn;
        self.escrow.insert(&id, sn, &said)?;

        Ok(())
    }

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log
            .log_event(&PostgresWriteTxnMode::CreateNew, event)?;
        let said = event.event_message.digest().unwrap();

        self.escrow.insert(id, sn, &said)?;

        Ok(())
    }

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::EventIter, Self::Error> {
        let saids = self.escrow.get(identifier, sn)?;
        let saids_vec: Vec<_> = saids.collect();

        let log = Arc::clone(&self.log);

        let events = saids_vec.into_iter().filter_map(move |said| {
            log.get_signed_event(&said)
                .ok()
                .flatten()
                .map(|el| el.signed_event_message)
        });

        Ok(Box::new(events))
    }

    fn get_from_sn(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        let saids: Vec<_> = self.escrow.get_greater_than(identifier, sn)?.collect();
        let log = Arc::clone(&self.log);

        let events = saids.into_iter().filter_map(move |said| {
            log.get_signed_event(&said)
                .ok()
                .flatten()
                .map(|el| el.signed_event_message)
        });

        Ok(Box::new(events))
    }

    fn remove(&self, event: &KeriEvent<KeyEvent>) {
        let said = event.digest().unwrap();
        let id = event.data.get_prefix();
        let sn = event.data.sn;
        self.escrow.remove(&id, sn, &said).unwrap();
    }

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<bool, PostgresError> {
        Ok(self
            .escrow
            .get(id, sn)?
            .find(|said| said == digest)
            .is_some())
    }
}

pub struct PostgresSnKeyDatabase {
    pool: PgPool,
    escrow_type: &'static str,
}

impl PostgresSnKeyDatabase {
    pub fn new(pool: PgPool, escrow_type: &'static str) -> Self {
        Self { pool, escrow_type }
    }
}

impl SequencedEventDatabase for PostgresSnKeyDatabase {
    type DatabaseType = PgPool;

    type Error = PostgresError;

    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(db: Arc<Self::DatabaseType>, table_name: &'static str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self {
            pool: (*db).clone(),
            escrow_type: table_name,
        })
    }

    fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), PostgresError> {
        let id_str = identifier.to_string();
        let digest_bytes = rkyv_adapter::serialize_said(digest)?;
        async_std::task::block_on(
            sqlx::query(
                "INSERT INTO escrow_events (escrow_type, identifier, sn, digest) \
                    VALUES ($1, $2, $3, $4) \
                    ON CONFLICT DO NOTHING",
            )
            .bind(self.escrow_type)
            .bind(&id_str)
            .bind(sn as i64)
            .bind(digest_bytes.as_ref())
            .execute(&self.pool),
        )?;
        Ok(())
    }

    fn get(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, PostgresError> {
        let id_str = identifier.to_string();
        let rows = async_std::task::block_on(
            sqlx::query(
                "SELECT digest FROM escrow_events \
                    WHERE escrow_type = $1 AND identifier = $2 AND sn = $3",
            )
            .bind(self.escrow_type)
            .bind(&id_str)
            .bind(sn as i64)
            .fetch_all(&self.pool),
        )?;

        let saids: Vec<SelfAddressingIdentifier> = rows
            .into_iter()
            .filter_map(|row| {
                let bytes: Vec<u8> = row.get("digest");
                rkyv_adapter::deserialize_said(&bytes).ok()
            })
            .collect();

        Ok(Box::new(saids.into_iter()))
    }

    fn get_greater_than(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, PostgresError> {
        let id_str = identifier.to_string();
        let rows = async_std::task::block_on(
            sqlx::query(
                "SELECT digest FROM escrow_events \
                    WHERE escrow_type = $1 AND identifier = $2 AND sn >= $3 \
                    ORDER BY sn ASC",
            )
            .bind(self.escrow_type)
            .bind(&id_str)
            .bind(sn as i64)
            .fetch_all(&self.pool),
        )?;

        let saids: Vec<SelfAddressingIdentifier> = rows
            .into_iter()
            .filter_map(|row| {
                let bytes: Vec<u8> = row.get("digest");
                rkyv_adapter::deserialize_said(&bytes).ok()
            })
            .collect();

        Ok(Box::new(saids.into_iter()))
    }

    fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<(), PostgresError> {
        let id_str = identifier.to_string();
        let digest_bytes = serialize_said(said)?;
        async_std::task::block_on(
            sqlx::query(
                "DELETE FROM escrow_events \
                    WHERE escrow_type = $1 AND identifier = $2 AND sn = $3 AND digest = $4",
            )
            .bind(self.escrow_type)
            .bind(&id_str)
            .bind(sn as i64)
            .bind(digest_bytes.as_ref())
            .execute(&self.pool),
        )?;
        Ok(())
    }
}
