use std::sync::Arc;

use sqlx::{postgres::PgPoolOptions, PgPool, Row};

use crate::database::{postgres::error::PostgresError, EventDatabase};
use crate::event::KeyEvent;
use crate::event_message::msg::KeriEvent;
use crate::prefix::IdentifierPrefix;
use crate::state::IdentifierState;

mod error;
mod escrow_database;
mod loging;

pub use loging::PostgresLogDatabase;

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

    // Helper: run async code from sync context
    fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        async_std::task::block_on(future)
    }

    // Async helper: get key state from database
    async fn get_key_state_async(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        let key = id.to_string();
        let result = sqlx::query("SELECT state_data FROM key_states WHERE identifier = $1")
            .bind(&key)
            .fetch_optional(&self.pool)
            .await
            .ok()?;

        result.map(|row| {
            let bytes: Vec<u8> = row.get("state_data");
            rkyv::from_bytes::<IdentifierState, rkyv::rancor::Error>(&bytes).ok()
        })?
    }

    // Async helper: update key state in database
    async fn update_key_state_async(
        &self,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), PostgresError> {
        let key = event.data.prefix.to_string();

        // Get current state
        let current_state = self.get_key_state_async(&event.data.prefix).await;
        let key_state = current_state.unwrap_or_default();

        // Apply event to get new state
        let new_state = key_state
            .apply(event)
            .map_err(|_e| PostgresError::AlreadySaved(event.digest().unwrap()))?;

        let state_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&new_state)?;

        sqlx::query(
            "INSERT INTO key_states (identifier, state_data) VALUES ($1, $2)
             ON CONFLICT (identifier) DO UPDATE SET state_data = EXCLUDED.state_data",
        )
        .bind(&key)
        .bind(state_bytes.as_slice())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Async helper: save event to KEL index
    async fn save_to_kel_async(&self, event: &KeriEvent<KeyEvent>) -> Result<(), PostgresError> {
        let digest = event.digest().map_err(|_e| PostgresError::MissingDigest)?;
        let digest_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&digest)?;

        let id = event.data.prefix.to_string();
        let sn = event.data.sn as i64;

        sqlx::query(
            "INSERT INTO kels (identifier, sn, digest) VALUES ($1, $2, $3)
             ON CONFLICT (identifier, sn) DO NOTHING",
        )
        .bind(&id)
        .bind(sn)
        .bind(digest_bytes.as_slice())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

impl EventDatabase for PostgresDatabase {
    type Error = PostgresError;

    type LogDatabaseType = PostgresLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: crate::event_message::signed_event_message::SignedEventMessage,
        _id: &crate::prefix::IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        self.block_on(async {
            // 1. Update key state
            self.update_key_state_async(&signed_event.event_message)
                .await?;

            // 2. Log the event (store event + signatures)
            self.log_db.log_event_async(&signed_event).await?;

            // 3. Save to KEL index
            self.save_to_kel_async(&signed_event.event_message).await?;

            Ok(())
        })
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
        self.block_on(self.get_key_state_async(id))
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
    #[ignore] // Run with: cargo test -p keri-core --features postgres-backend -- --ignored
    async fn test_postgres_migrations() {
        let db = PostgresDatabase::new(&get_database_url())
            .await
            .expect("Failed to connect to database");

        db.run_migrations().await.expect("Failed to run migrations");

        println!("Migrations completed successfully!");
    }

    #[async_std::test]
    #[ignore] // Run with: cargo test -p keri-core --features postgres-backend -- --ignored
    async fn test_add_kel_finalized_event() {
        use crate::actor::event_generator;
        use crate::event::sections::threshold::SignatureThreshold;
        use crate::event_message::signed_event_message::SignedEventMessage;
        use crate::prefix::BasicPrefix;
        use crate::signer::{CryptoBox, KeyManager};

        // Setup database
        let db = PostgresDatabase::new(&get_database_url())
            .await
            .expect("Failed to connect to database");
        db.run_migrations().await.expect("Failed to run migrations");

        // Create a key manager
        let km = CryptoBox::new().unwrap();
        let pk = BasicPrefix::Ed25519(km.public_key());
        let npk = BasicPrefix::Ed25519(km.next_public_key());

        // Generate inception event
        let icp = event_generator::incept(
            vec![pk.clone()],
            SignatureThreshold::Simple(1),
            vec![npk],
            SignatureThreshold::Simple(1),
            vec![], // no witnesses
            0,
        )
        .unwrap();

        // Sign the event
        let signature = km.sign(&icp.encode().unwrap()).unwrap();
        let signed_event = SignedEventMessage::new(&icp, vec![signature], None, None);

        // Get the identifier
        let prefix = icp.data.prefix.clone();

        // Verify no state exists before
        let state_before = db.get_key_state(&prefix);
        assert!(
            state_before.is_none(),
            "State should not exist before inception"
        );

        // Add the event
        db.add_kel_finalized_event(signed_event, &prefix)
            .expect("Failed to add event");

        // Verify state exists after
        let state_after = db.get_key_state(&prefix);
        assert!(state_after.is_some(), "State should exist after inception");

        let state = state_after.unwrap();
        assert_eq!(state.prefix, prefix);
        assert_eq!(state.sn, 0);

        println!("add_kel_finalized_event test passed!");
    }
}
