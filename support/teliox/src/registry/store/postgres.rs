//! Registries in PostgreSQL, in the tables of the keri-core migrations.

use said::SelfAddressingIdentifier;
use sqlx::PgPool;

use super::{block_from_text, block_to_text, RegistryStore};
use crate::registry::{RegistryError, RegistryMessage, StateBlock};

pub struct PostgresRegistryStore {
    pool: PgPool,
}

fn storage(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Storage(e.to_string())
}

impl PostgresRegistryStore {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn put(&self, query: &'static str, key: String, value: String) -> Result<(), RegistryError> {
        async_std::task::block_on(sqlx::query(query).bind(key).bind(value).execute(&self.pool))
            .map(|_| ())
            .map_err(storage)
    }

    fn get(&self, query: &'static str, key: String) -> Result<Option<String>, RegistryError> {
        let row: Option<(String,)> =
            async_std::task::block_on(sqlx::query_as(query).bind(key).fetch_optional(&self.pool))
                .map_err(storage)?;
        Ok(row.map(|(value,)| value))
    }
}

impl RegistryStore for PostgresRegistryStore {
    fn save_event(&self, event: &RegistryMessage) -> Result<(), RegistryError> {
        let sn = i64::try_from(event.sn()).map_err(storage)?;
        async_std::task::block_on(
            sqlx::query(
                "INSERT INTO registry_events (registry, sn, said, body) VALUES ($1, $2, $3, $4) \
                 ON CONFLICT DO NOTHING",
            )
            .bind(event.registry()?.to_string())
            .bind(sn)
            .bind(event.said()?.to_string())
            .bind(event.encode())
            .execute(&self.pool),
        )
        .map(|_| ())
        .map_err(storage)
    }

    fn events(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Vec<RegistryMessage>, RegistryError> {
        let rows: Vec<(Vec<u8>,)> = async_std::task::block_on(
            sqlx::query_as(
                "SELECT body FROM registry_events WHERE registry = $1 \
                 ORDER BY sn, said COLLATE \"C\"",
            )
            .bind(registry.to_string())
            .fetch_all(&self.pool),
        )
        .map_err(storage)?;
        rows.iter()
            .map(|(body,)| RegistryMessage::parse(body))
            .collect()
    }

    fn save_block(&self, block: &StateBlock) -> Result<(), RegistryError> {
        self.put(
            "INSERT INTO registry_blocks (blid, block) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            block.blid()?.to_string(),
            block_to_text(block)?,
        )
    }

    fn block(&self, blid: &SelfAddressingIdentifier) -> Result<Option<StateBlock>, RegistryError> {
        self.get(
            "SELECT block FROM registry_blocks WHERE blid = $1",
            blid.to_string(),
        )?
        .map(|text| block_from_text(&text))
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    use keri_core::database::postgres::PostgresDatabase;
    use sqlx::postgres::PgPoolOptions;

    fn get_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/keri_test".to_string())
    }

    /// Ensures the test database exists with a fresh schema, serialized across parallel tests.
    fn ensure_schema() {
        static INIT: std::sync::Mutex<bool> = std::sync::Mutex::new(false);
        let mut done = INIT.lock().unwrap();
        if *done {
            return;
        }
        let result = std::panic::catch_unwind(|| {
            async_std::task::block_on(async {
                let url = get_database_url();
                let (base, db_name) = url.rsplit_once('/').expect("Invalid DATABASE_URL");
                let admin = PgPoolOptions::new()
                    .max_connections(2)
                    .connect(&format!("{}/postgres", base))
                    .await
                    .expect("Failed to connect to admin db");
                // Drop and recreate to get a clean schema
                let _ = sqlx::query(&format!(
                    "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
                    db_name
                ))
                .execute(&admin)
                .await;
                sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
                    .execute(&admin)
                    .await
                    .expect("Failed to create test database");

                let db = PostgresDatabase::new(&url)
                    .await
                    .expect("Failed to connect to database");
                db.run_migrations().await.expect("Failed to run migrations");
            });
        });
        if result.is_err() {
            panic!("ensure_schema failed — check DATABASE_URL and postgres connection");
        }
        *done = true;
    }

    async fn setup_pool() -> sqlx::PgPool {
        ensure_schema();
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&get_database_url())
            .await
            .expect("Failed to connect to database")
    }

    #[async_std::test]
    async fn the_postgres_store_keeps_registries() {
        let pool = setup_pool().await;
        crate::registry::store::conformance::check(&super::PostgresRegistryStore::new(pool));
    }
}
