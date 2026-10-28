//! Registries in PostgreSQL, in the tables of the keri-core migrations.

use said::SelfAddressingIdentifier;
use sqlx::PgPool;

use super::{block_from_text, block_to_text, RegistryStore};
use crate::registry::{BlindedState, RegistryError, RegistryMessage, Salt};

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
            .bind(event.encode()?)
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

    fn save_block(&self, block: &BlindedState) -> Result<(), RegistryError> {
        self.put(
            "INSERT INTO registry_blocks (blid, block) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            block.blid.to_string(),
            block_to_text(block)?,
        )
    }

    fn block(
        &self,
        blid: &SelfAddressingIdentifier,
    ) -> Result<Option<BlindedState>, RegistryError> {
        self.get(
            "SELECT block FROM registry_blocks WHERE blid = $1",
            blid.to_string(),
        )?
        .map(|text| block_from_text(&text))
        .transpose()
    }

    fn save_salt(
        &self,
        registry: &SelfAddressingIdentifier,
        salt: &Salt,
    ) -> Result<(), RegistryError> {
        self.put(
            "INSERT INTO registry_salts (registry, salt) VALUES ($1, $2) \
             ON CONFLICT (registry) DO UPDATE SET salt = EXCLUDED.salt",
            registry.to_string(),
            salt.to_qb64(),
        )
    }

    fn salt(&self, registry: &SelfAddressingIdentifier) -> Result<Option<Salt>, RegistryError> {
        self.get(
            "SELECT salt FROM registry_salts WHERE registry = $1",
            registry.to_string(),
        )?
        .map(|qb64| Salt::from_qb64(&qb64))
        .transpose()
    }
}

#[cfg(test)]
mod tests {
    #[async_std::test]
    async fn the_postgres_store_keeps_registries() {
        let pool = crate::database::postgres::tests::setup_pool().await;
        crate::registry::store::conformance::check(&super::PostgresRegistryStore::new(pool));
    }
}
