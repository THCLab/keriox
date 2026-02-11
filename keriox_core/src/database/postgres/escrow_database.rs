use std::sync::Arc;

use said::SelfAddressingIdentifier;
use sqlx::{PgPool, Row};

use crate::{
    database::{
        postgres::{error::PostgresError, PostgresDatabase, PostgresLogDatabase},
        redb::rkyv_adapter,
        EscrowCreator, EscrowDatabase, LogDatabase as _, SequencedEventDatabase,
    },
    event_message::signed_event_message::SignedEventMessage,
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
        todo!()
    }

    fn insert(
        &self,
        event: &crate::event_message::signed_event_message::SignedEventMessage,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn insert_key_value(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        event: &crate::event_message::signed_event_message::SignedEventMessage,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::EventIter, Self::Error> {
        todo!()
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

    fn remove(&self, event: &crate::event_message::msg::KeriEvent<crate::event::KeyEvent>) {
        todo!()
    }

    fn contains(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<bool, Self::Error> {
        todo!()
    }
}

pub struct PostgresSnKeyDatabase {
    pool: PgPool,
    //partiallu_signed, out_of_order
    escrow_type: &'static str,
}

impl PostgresSnKeyDatabase {
    pub fn new(pool: PgPool, escrow_type: &'static str) -> Self {
        Self { pool, escrow_type }
    }

    //todo: other
}

impl SequencedEventDatabase for PostgresSnKeyDatabase {
    type DatabaseType = PgPool;

    type Error = PostgresError;

    type DigestIter = Box<dyn Iterator<Item = SelfAddressingIdentifier>>;

    fn new(db: Arc<Self::DatabaseType>, table_name: &'static str) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        todo!()
    }

    fn insert(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get(&self, identifier: &IdentifierPrefix, sn: u64) -> Result<Self::DigestIter, Self::Error> {
        todo!()
    }

    fn get_greater_than(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        let id_str = identifier.to_string();
        let rows = async_std::task::block_on(
            sqlx::query(
                "SELECT digest FROM escrow_events \
                 WHERE escrow_type = $1 AND identifier = $2 AND sn >= $3 \
                 ORDER BY sn",
            )
            .bind(self.escrow_type)
            .bind(&id_str)
            .bind(sn as i64)
            .fetch_all(&self.pool),
        )?;

        let digests = rows
            .into_iter()
            .filter_map(|row| {
                let bytes: Vec<u8> = row.get("digest");
                rkyv_adapter::deserialize_said(&bytes).ok()
            })
            .collect::<Vec<_>>();

        Ok(Box::new(digests.into_iter()))
    }

    fn remove(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
