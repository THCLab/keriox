use std::sync::Arc;

use said::SelfAddressingIdentifier;
use sqlx::PgPool;

use crate::{
    database::{
        postgres::{error::PostgresError, PostgresDatabase, PostgresLogDatabase},
        EscrowCreator, EscrowDatabase, SequencedEventDatabase,
    },
    event_message::signed_event_message::SignedEventMessage,
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
        id: &crate::prefix::IdentifierPrefix,
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
        id: &crate::prefix::IdentifierPrefix,
        sn: u64,
        event: &crate::event_message::signed_event_message::SignedEventMessage,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get(
        &self,
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        todo!()
    }

    fn get_from_sn(
        &self,
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::EventIter, Self::Error> {
        todo!()
    }

    fn remove(&self, event: &crate::event_message::msg::KeriEvent<crate::event::KeyEvent>) {
        todo!()
    }

    fn contains(
        &self,
        id: &crate::prefix::IdentifierPrefix,
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
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
        digest: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get(
        &self,
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        todo!()
    }

    fn get_greater_than(
        &self,
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
    ) -> Result<Self::DigestIter, Self::Error> {
        todo!()
    }

    fn remove(
        &self,
        identifier: &crate::prefix::IdentifierPrefix,
        sn: u64,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
