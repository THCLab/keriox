use std::sync::Arc;

use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::database::{postgres::error::PostgresError, EventDatabase};

mod error;
mod escrow_database;
mod loging;
pub mod oobi_storage;

pub use loging::PostgresLogDatabase;
pub use oobi_storage::PostgresOobiStorage;

pub struct PgConfig {
    pub database_url: String,
}

pub struct PostgresDatabase {
    pool: PgPool,
    log_db: Arc<PostgresLogDatabase>,
}

impl PostgresDatabase {
    pub async fn new(database_url: &str) -> Result<Self, PostgresError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;

        let log_db = Arc::new(PostgresLogDatabase::new(pool.clone()));

        Ok(Self { pool, log_db })
    }

    pub async fn run_migrations(&self) -> Result<(), PostgresError> {
        sqlx::migrate!("src/database/postgres/migrations")
            .run(&self.pool)
            .await?;
        Ok(())
    }
}

impl EventDatabase for PostgresDatabase {
    type Error = PostgresError;

    type LogDatabaseType = PostgresLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        todo!()
    }

    fn add_kel_finalized_event(
        &self,
        event: crate::event_message::signed_event_message::SignedEventMessage,
        id: &crate::prefix::IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn add_receipt_t(
        &self,
        receipt: crate::event_message::signed_event_message::SignedTransferableReceipt,
        id: &crate::prefix::IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn add_receipt_nt(
        &self,
        receipt: crate::event_message::signed_event_message::SignedNontransferableReceipt,
        id: &crate::prefix::IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get_key_state(
        &self,
        id: &crate::prefix::IdentifierPrefix,
    ) -> Option<crate::state::IdentifierState> {
        todo!()
    }

    fn get_kel_finalized_events(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = super::timestamped::TimestampedSignedEventMessage>>
    {
        None::<std::vec::IntoIter<super::timestamped::TimestampedSignedEventMessage>>
    }

    fn get_receipts_t(
        &self,
        params: super::QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = crate::event_message::signature::Transferable>>
    {
        None::<std::vec::IntoIter<crate::event_message::signature::Transferable>>
    }

    fn get_receipts_nt(
        &self,
        params: super::QueryParameters,
    ) -> Option<
        impl DoubleEndedIterator<
            Item = crate::event_message::signed_event_message::SignedNontransferableReceipt,
        >,
    > {
        None::<
            std::vec::IntoIter<
                crate::event_message::signed_event_message::SignedNontransferableReceipt,
            >,
        >
    }

    fn accept_to_kel(
        &self,
        event: &crate::event_message::msg::KeriEvent<crate::event::KeyEvent>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    #[cfg(feature = "query")]
    fn save_reply(&self, reply: crate::query::reply_event::SignedReply) -> Result<(), Self::Error> {
        todo!()
    }

    #[cfg(feature = "query")]
    fn get_reply(
        &self,
        id: &crate::prefix::IdentifierPrefix,
        from_who: &crate::prefix::IdentifierPrefix,
    ) -> Option<crate::query::reply_event::SignedReply> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/keri_test".to_string())
    }

    #[async_std::test]
    #[ignore]
    async fn test_postgres_migrations() {
        let db = PostgresDatabase::new(&get_database_url())
            .await
            .expect("Failed to connect to database");

        db.run_migrations().await.expect("Failed to run migrations");

        println!("Migrations completed successfully!");
    }

    #[cfg(all(feature = "mailbox", feature = "oobi-manager"))]
    #[async_std::test]
    #[ignore]
    async fn test_simple_controller_with_postgres() {
        use crate::{
            actor::simple_controller::SimpleController, oobi_manager::OobiManager,
            processor::escrow::EscrowConfig, signer::CryptoBox,
        };
        use std::sync::Mutex;

        let db = PostgresDatabase::new(&get_database_url())
            .await
            .expect("Failed to connect to database");

        db.run_migrations().await.expect("Failed to run migrations");

        let db = Arc::new(db);

        let pool = sqlx::PgPool::connect(&get_database_url())
            .await
            .expect("Failed to create pool");
        let oobi_storage = PostgresOobiStorage::new(pool);
        let oobi_manager = OobiManager::new_with_storage(oobi_storage);

        let key_manager = Arc::new(Mutex::new(CryptoBox::new().unwrap()));

        let controller = SimpleController::new_with_oobi_manager(
            db,
            key_manager,
            oobi_manager,
            EscrowConfig::default(),
        );

        assert!(
            controller.is_ok(),
            "Failed to create SimpleController with Postgres"
        );

        println!("SimpleController with Postgres created successfully!");
    }
}
