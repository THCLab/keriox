use std::{sync::Arc, vec::IntoIter};

use cesrox::primitives::CesrPrimitive;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

use crate::{
    database::{postgres::error::PostgresError, redb::rkyv_adapter, EventDatabase, LogDatabase},
    event_message::signed_event_message::SignedEventMessage,
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

mod error;
mod escrow_database;
mod loging;
pub mod oobi_storage;

pub use loging::PostgresLogDatabase;
pub use oobi_storage::PostgresOobiStorage;

use super::{timestamped::TimestampedSignedEventMessage, QueryParameters};

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

    async fn update_key_state(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        event: &crate::event_message::msg::KeriEvent<crate::event::KeyEvent>,
    ) -> Result<(), PostgresError> {
        let prefix = event.data.prefix.to_str();

        let row = sqlx::query("SELECT state_data FROM key_states WHERE identifier = $1")
            .bind(&prefix)
            .fetch_optional(&mut **tx)
            .await?;

        let current_state = match row {
            Some(row) => {
                let bytes: Vec<u8> = row.get("state_data");
                rkyv_adapter::deserialize_identifier_state(&bytes)?
            }
            None => IdentifierState::default(),
        };

        let new_state = current_state
            .apply(event)
            .map_err(|_| PostgresError::AlreadySaved(event.digest().unwrap()))?;
        let state_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&new_state)?;

        sqlx::query(
            "INSERT INTO key_states (identifier, state_data) VALUES ($1, $2) \
             ON CONFLICT (identifier) DO UPDATE SET state_data = $2",
        )
        .bind(&prefix)
        .bind(state_bytes.as_ref())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }

    async fn save_to_kel(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        event: &crate::event_message::msg::KeriEvent<crate::event::KeyEvent>,
    ) -> Result<(), PostgresError> {
        let prefix = event.data.prefix.to_str();
        let digest = event.digest().map_err(|_| PostgresError::MissingDigest)?;
        let sn = event.data.sn as i64;
        let serialized_digest = rkyv_adapter::serialize_said(&digest)?;

        sqlx::query(
            "INSERT INTO kels (identifier, sn, digest) VALUES ($1, $2, $3) \
             ON CONFLICT (identifier, sn) DO NOTHING",
        )
        .bind(&prefix)
        .bind(sn)
        .bind(serialized_digest.as_ref())
        .execute(&mut **tx)
        .await?;

        Ok(())
    }
}

impl EventDatabase for PostgresDatabase {
    type Error = PostgresError;

    type LogDatabaseType = PostgresLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        return self.log_db.clone();
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        async_std::task::block_on(async {
            let mut tx = self.pool.begin().await?;

            self.update_key_state(&mut tx, &signed_event.event_message)
                .await?;
            self.save_to_kel(&mut tx, &signed_event.event_message)
                .await?;
            self.log_db
                .log_event_with_tx(&mut tx, &signed_event)
                .await?;

            tx.commit().await?;
            Ok(())
        })
    }

    fn add_receipt_t(
        &self,
        receipt: crate::event_message::signed_event_message::SignedTransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn add_receipt_nt(
        &self,
        receipt: crate::event_message::signed_event_message::SignedNontransferableReceipt,
        id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get_key_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        let key = id.to_str();
        let row = async_std::task::block_on(
            sqlx::query("SELECT state_data FROM key_states WHERE identifier = $1")
                .bind(&key)
                .fetch_optional(&self.pool),
        )
        .ok()??;

        let bytes: Vec<u8> = row.get("state_data");
        Some(rkyv_adapter::deserialize_identifier_state(&bytes).ok()?)
    }

    fn get_kel_finalized_events(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = TimestampedSignedEventMessage>> {
        let result = match params {
            QueryParameters::BySn { id, sn } => self.get_kel(&id, sn, 1),
            QueryParameters::Range { id, start, limit } => self.get_kel(&id, start, limit),
            QueryParameters::All { id } => self.get_kel(id, 0, u64::MAX),
        };

        match result {
            Ok(kel) if kel.is_empty() => None,
            Ok(kel) => Some(kel.into_iter()),
            Err(_) => None::<std::vec::IntoIter<TimestampedSignedEventMessage>>,
        }
    }

    fn get_receipts_t(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = crate::event_message::signature::Transferable>>
    {
        None::<IntoIter<crate::event_message::signature::Transferable>>
    }

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<
        impl DoubleEndedIterator<
            Item = crate::event_message::signed_event_message::SignedNontransferableReceipt,
        >,
    > {
        None::<IntoIter<crate::event_message::signed_event_message::SignedNontransferableReceipt>>
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
        id: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
    ) -> Option<crate::query::reply_event::SignedReply> {
        todo!()
    }
}

impl PostgresDatabase {
    fn get_kel(
        &self,
        id: &IdentifierPrefix,
        from: u64,
        limit: u64,
    ) -> Result<Vec<TimestampedSignedEventMessage>, PostgresError> {
        let prefix = id.to_str();
        let from_sn = from as i64;

        async_std::task::block_on(async {
            let rows = if limit == u64::MAX {
                sqlx::query(
                    "SELECT digest FROM kels WHERE identifier = $1 AND sn >= $2 ORDER BY sn ASC",
                )
                .bind(&prefix)
                .bind(from_sn)
                .fetch_all(&self.pool)
                .await?
            } else {
                let end_sn = from.saturating_add(limit) as i64;
                sqlx::query(
                    "SELECT digest FROM kels WHERE identifier = $1 AND sn >= $2 AND sn < $3 ORDER BY sn ASC",
                )
                .bind(&prefix)
                .bind(from_sn)
                .bind(end_sn)
                .fetch_all(&self.pool)
                .await?
            };

            let mut events = Vec::new();
            for row in rows {
                let digest_bytes: Vec<u8> = row.get("digest");
                let said = rkyv_adapter::deserialize_said(&digest_bytes)?;
                if let Some(timestamped_event) = self.log_db.get_signed_event(&said)? {
                    events.push(timestamped_event);
                }
            }
            Ok(events)
        })
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

    #[cfg(all(feature = "mailbox", feature = "oobi-manager"))]
    #[async_std::test]
    #[ignore]
    async fn test_postgres_incept() {
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

        let mut controller = SimpleController::new_with_oobi_manager(
            db,
            key_manager,
            oobi_manager,
            EscrowConfig::default(),
        )
        .expect("Failed to create SimpleController");

        let signed_icp = controller
            .incept(None, None, None)
            .expect("Failed to incept");

        println!(
            "Inception event created: {:?}",
            signed_icp.event_message.data.get_prefix()
        );

        let state = controller.get_state();
        assert!(state.is_some(), "State should exist after inception");

        let state = state.unwrap();
        assert_eq!(state.sn, 0, "Inception event should have sn 0");
        assert_eq!(
            state.prefix,
            signed_icp.event_message.data.get_prefix(),
            "State prefix should match inception prefix"
        );

        println!("Inception test passed! Prefix: {}", controller.prefix());
    }

    #[cfg(all(feature = "mailbox", feature = "oobi-manager"))]
    #[async_std::test]
    #[ignore]
    async fn test_postgres_get_kel() {
        use crate::{
            actor::simple_controller::SimpleController, database::QueryParameters,
            event_message::EventTypeTag, oobi_manager::OobiManager,
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

        let mut controller = SimpleController::new_with_oobi_manager(
            db.clone(),
            key_manager,
            oobi_manager,
            EscrowConfig::default(),
        )
        .expect("Failed to create SimpleController");

        let signed_icp = controller
            .incept(None, None, None)
            .expect("Failed to incept");

        let prefix = signed_icp.event_message.data.get_prefix();

        // Retrieve by sn=0
        let kel_sn0 = db.get_kel(&prefix, 0, 1).expect("get_kel failed");
        assert_eq!(kel_sn0.len(), 1);
        assert_eq!(
            kel_sn0[0].signed_event_message.event_message.event_type,
            EventTypeTag::Icp
        );
        assert_eq!(
            kel_sn0[0]
                .signed_event_message
                .event_message
                .data
                .get_prefix(),
            prefix
        );

        // Retrieve full KEL via get_kel_finalized_events
        let full_kel: Vec<_> = db
            .get_kel_finalized_events(QueryParameters::All { id: &prefix })
            .expect("Full KEL should exist")
            .collect();
        assert_eq!(full_kel.len(), 1);
        assert_eq!(
            full_kel[0].signed_event_message.event_message.event_type,
            EventTypeTag::Icp
        );

        // Retrieve via BySn
        let by_sn: Vec<_> = db
            .get_kel_finalized_events(QueryParameters::BySn {
                id: prefix.clone(),
                sn: 0,
            })
            .expect("BySn should return event")
            .collect();
        assert_eq!(by_sn.len(), 1);

        // Non-existent sn returns None
        let empty = db.get_kel_finalized_events(QueryParameters::BySn {
            id: prefix.clone(),
            sn: 99,
        });
        assert!(empty.is_none());

        println!("test_postgres_get_kel passed! Prefix: {}", prefix);
    }
}
