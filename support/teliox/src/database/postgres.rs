use crate::{
    database::{TelEscrowDatabase, TelEventDatabase},
    error::Error,
    event::{Event, verifiable_event::VerifiableEvent},
};
use keri_core::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;
use sqlx::PgPool;

pub struct PostgresTelDatabase {
    pool: PgPool,
}

impl PostgresTelDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    fn get_events_from_index(
        &self,
        index_table: &'static str,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        let id_str = id.to_string();
        let pool = self.pool.clone();
        let events: Vec<VerifiableEvent> = async_std::task::block_on(async move {
            let query =
                format!("SELECT digest FROM {index_table} WHERE identifier = $1 ORDER BY sn ASC");
            let rows: Vec<(String,)> = sqlx::query_as(&query)
                .bind(&id_str)
                .fetch_all(&pool)
                .await
                .unwrap_or_default();

            let mut events = Vec::new();
            for (digest,) in rows {
                let maybe: Option<(Vec<u8>,)> =
                    sqlx::query_as("SELECT event_data FROM tel_events WHERE digest = $1")
                        .bind(&digest)
                        .fetch_optional(&pool)
                        .await
                        .unwrap_or(None);

                if let Some((data,)) = maybe {
                    if let Ok(event) = serde_cbor::from_slice::<VerifiableEvent>(&data) {
                        events.push(event);
                    }
                }
            }
            events
        });
        if events.is_empty() {
            None
        } else {
            Some(events.into_iter())
        }
    }
}

impl TelEventDatabase for PostgresTelDatabase {
    fn add_new_event(&self, event: VerifiableEvent, _id: &IdentifierPrefix) -> Result<(), Error> {
        let pool = self.pool.clone();
        async_std::task::block_on(async move {
            let digest = event
                .event
                .get_digest()
                .map_err(|_| Error::Generic("Event has no digest".to_string()))?;
            let digest_str = digest.to_string();
            let event_data = serde_cbor::to_vec(&event)
                .map_err(|e| Error::Generic(format!("Serialization error: {}", e)))?;

            let mut tx = pool
                .begin()
                .await
                .map_err(|e| Error::Generic(e.to_string()))?;

            sqlx::query(
                "INSERT INTO tel_events (digest, event_data) VALUES ($1, $2) \
                 ON CONFLICT (digest) DO NOTHING",
            )
            .bind(&digest_str)
            .bind(&event_data)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;

            let id_str = event.event.get_prefix().to_string();
            let sn = event.event.get_sn() as i64;

            match &event.event {
                Event::Management(_) => {
                    sqlx::query(
                        "INSERT INTO management_tels (identifier, sn, digest) \
                         VALUES ($1, $2, $3) ON CONFLICT (identifier, sn) DO NOTHING",
                    )
                    .bind(&id_str)
                    .bind(sn)
                    .bind(&digest_str)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Error::Generic(e.to_string()))?;
                }
                Event::Vc(_) => {
                    sqlx::query(
                        "INSERT INTO vc_tels (identifier, sn, digest) \
                         VALUES ($1, $2, $3) ON CONFLICT (identifier, sn) DO NOTHING",
                    )
                    .bind(&id_str)
                    .bind(sn)
                    .bind(&digest_str)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Error::Generic(e.to_string()))?;
                }
            }

            tx.commit()
                .await
                .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn get_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.get_events_from_index("vc_tels", id)
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.get_events_from_index("management_tels", id)
    }

    fn log_event(&self, event: &VerifiableEvent) -> Result<(), Error> {
        let pool = self.pool.clone();
        let digest = event
            .event
            .get_digest()
            .map_err(|_| Error::Generic("Event has no digest".to_string()))?;
        let digest_str = digest.to_string();
        let event_data = serde_cbor::to_vec(event)
            .map_err(|e| Error::Generic(format!("Serialization error: {}", e)))?;

        async_std::task::block_on(async move {
            sqlx::query(
                "INSERT INTO tel_events (digest, event_data) VALUES ($1, $2) \
                 ON CONFLICT (digest) DO NOTHING",
            )
            .bind(&digest_str)
            .bind(&event_data)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn get_event(
        &self,
        digest: &SelfAddressingIdentifier,
    ) -> Result<Option<VerifiableEvent>, Error> {
        let pool = self.pool.clone();
        let digest_str = digest.to_string();
        async_std::task::block_on(async move {
            let maybe: Option<(Vec<u8>,)> =
                sqlx::query_as("SELECT event_data FROM tel_events WHERE digest = $1")
                    .bind(&digest_str)
                    .fetch_optional(&pool)
                    .await
                    .map_err(|e| Error::Generic(e.to_string()))?;

            match maybe {
                None => Ok(None),
                Some((data,)) => {
                    let event = serde_cbor::from_slice::<VerifiableEvent>(&data)
                        .map_err(|e| Error::Generic(format!("Deserialization error: {}", e)))?;
                    Ok(Some(event))
                }
            }
        })
    }
}

pub struct PostgresTelEscrowDatabase {
    pool: PgPool,
}

impl PostgresTelEscrowDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl TelEscrowDatabase for PostgresTelEscrowDatabase {
    fn missing_issuer_insert(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let kel = kel_digest.to_string();
        let tel = tel_digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "INSERT INTO tel_missing_issuer_escrow (kel_digest, tel_digest) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(&kel)
            .bind(&tel)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn missing_issuer_get(
        &self,
        kel_digest: &str,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        let pool = self.pool.clone();
        let kel = kel_digest.to_string();
        async_std::task::block_on(async move {
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT tel_digest FROM tel_missing_issuer_escrow WHERE kel_digest = $1",
            )
            .bind(&kel)
            .fetch_all(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;

            rows.into_iter()
                .map(|(s,)| {
                    s.parse::<SelfAddressingIdentifier>()
                        .map_err(|e| Error::Generic(format!("Invalid digest: {}", e)))
                })
                .collect()
        })
    }

    fn missing_issuer_remove(
        &self,
        kel_digest: &str,
        tel_digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let kel = kel_digest.to_string();
        let tel = tel_digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "DELETE FROM tel_missing_issuer_escrow \
                 WHERE kel_digest = $1 AND tel_digest = $2",
            )
            .bind(&kel)
            .bind(&tel)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn out_of_order_insert(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let id_str = id.to_string();
        let sn_i = sn as i64;
        let dig = digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "INSERT INTO tel_out_of_order_escrow (identifier, sn, tel_digest) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            )
            .bind(&id_str)
            .bind(sn_i)
            .bind(&dig)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn out_of_order_get(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        let pool = self.pool.clone();
        let id_str = id.to_string();
        let sn_i = sn as i64;
        async_std::task::block_on(async move {
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT tel_digest FROM tel_out_of_order_escrow \
                 WHERE identifier = $1 AND sn = $2",
            )
            .bind(&id_str)
            .bind(sn_i)
            .fetch_all(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;

            rows.into_iter()
                .map(|(s,)| {
                    s.parse::<SelfAddressingIdentifier>()
                        .map_err(|e| Error::Generic(format!("Invalid digest: {}", e)))
                })
                .collect()
        })
    }

    fn out_of_order_remove(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let id_str = id.to_string();
        let sn_i = sn as i64;
        let dig = digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "DELETE FROM tel_out_of_order_escrow \
                 WHERE identifier = $1 AND sn = $2 AND tel_digest = $3",
            )
            .bind(&id_str)
            .bind(sn_i)
            .bind(&dig)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn missing_registry_insert(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let reg = registry_id.to_string();
        let dig = digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "INSERT INTO tel_missing_registry_escrow (registry_id, tel_digest) \
                 VALUES ($1, $2) ON CONFLICT DO NOTHING",
            )
            .bind(&reg)
            .bind(&dig)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn missing_registry_get(
        &self,
        registry_id: &str,
    ) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        let pool = self.pool.clone();
        let reg = registry_id.to_string();
        async_std::task::block_on(async move {
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT tel_digest FROM tel_missing_registry_escrow WHERE registry_id = $1",
            )
            .bind(&reg)
            .fetch_all(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;

            rows.into_iter()
                .map(|(s,)| {
                    s.parse::<SelfAddressingIdentifier>()
                        .map_err(|e| Error::Generic(format!("Invalid digest: {}", e)))
                })
                .collect()
        })
    }

    fn missing_registry_remove(
        &self,
        registry_id: &str,
        digest: &SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let pool = self.pool.clone();
        let reg = registry_id.to_string();
        let dig = digest.to_string();
        async_std::task::block_on(async move {
            sqlx::query(
                "DELETE FROM tel_missing_registry_escrow \
                 WHERE registry_id = $1 AND tel_digest = $2",
            )
            .bind(&reg)
            .bind(&dig)
            .execute(&pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database::{TelEscrowDatabase, TelEventDatabase},
        event::verifiable_event::VerifiableEvent,
    };
    use keri_core::database::postgres::PostgresDatabase;
    use sqlx::postgres::PgPoolOptions;

    // CESR stream with 3 TEL events: vcp (Management), bis (Vc issuance), brv (Vc revocation)
    const TEL_EVENTS: &str = r#"{"v":"KERI10JSON0000e0_","t":"vcp","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA","i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","ii":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","c":["NB"],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAABENMILl_3-wbKmzOR5IC4rOjwwXE-LFafC34vzduBn2O1{"v":"KERI10JSON000162_","t":"bis","d":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","ii":"EPyhGnPEzI1OjbmvNCEsiQfinmwxGcJgyDK_Nx9hnI2l","ra":{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"},"dt":"2023-06-30T08:04:23.180342+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAACEPBB-kmu3NQkuDUijczDscu6SMkOq_XznhufG2DFiveh{"v":"KERI10JSON000161_","t":"brv","d":"EBr1rgUjzKeGKRijXUkc-Sx_LzB1HUxyd3qB6zc8Jaga","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","p":"EH--8AOVXFyZ5HdshHVUjYIgrxqIRczzzbTZiZRzl6v8","ra":{"i":"EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN","s":"0","d":"EJPLd0ZMdbusC-nEQgXfVDcNWPkaZfhPAYH43ZqIrOOA"},"dt":"2023-06-30T08:04:23.186687+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAADEKtt7vosEnv-Y0QVRfZq5HFmRZ1e_l5NeJq-zq_wd2ht"#;

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
                let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)", db_name))
                    .execute(&admin)
                    .await;
                sqlx::query(&format!("CREATE DATABASE \"{}\"", db_name))
                    .execute(&admin)
                    .await
                    .expect("Failed to create test database");

                let db = PostgresDatabase::new(&url)
                    .await
                    .expect("Failed to connect to database");
                db.run_migrations()
                    .await
                    .expect("Failed to run migrations");
            });
        });
        if result.is_err() {
            panic!("ensure_schema failed — check DATABASE_URL and postgres connection");
        }
        *done = true;
    }

    async fn setup_pool() -> PgPool {
        ensure_schema();
        PgPoolOptions::new()
            .max_connections(5)
            .connect(&get_database_url())
            .await
            .expect("Failed to connect to database")
    }

    fn parse_tel_events() -> (VerifiableEvent, VerifiableEvent, VerifiableEvent) {
        let parsed = VerifiableEvent::parse(TEL_EVENTS.as_bytes()).unwrap();
        (parsed[0].clone(), parsed[1].clone(), parsed[2].clone())
    }

    #[async_std::test]
    async fn test_add_and_get_management_event() {
        let db = PostgresTelDatabase::new(setup_pool().await);
        let (vcp, _, _) = parse_tel_events();

        let id = vcp.event.get_prefix();
        db.add_new_event(vcp.clone(), &id).unwrap();

        let events: Vec<_> = db.get_management_events(&id).unwrap().collect();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0], vcp);
    }

    #[async_std::test]
    async fn test_add_and_get_vc_events() {
        let db = PostgresTelDatabase::new(setup_pool().await);
        let (_, iss, rev) = parse_tel_events();

        let id = iss.event.get_prefix();
        db.add_new_event(iss.clone(), &id).unwrap();
        db.add_new_event(rev.clone(), &id).unwrap();

        let events: Vec<_> = db.get_events(&id).unwrap().collect();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], iss);
        assert_eq!(events[1], rev);
    }

    #[async_std::test]
    async fn test_log_event_and_get_by_digest() {
        let db = PostgresTelDatabase::new(setup_pool().await);
        let (vcp, _, _) = parse_tel_events();

        db.log_event(&vcp).unwrap();

        let digest = vcp.event.get_digest().unwrap();
        let result = db.get_event(&digest).unwrap();
        assert_eq!(result, Some(vcp));
    }

    #[async_std::test]
    async fn test_get_event_missing_returns_none() {
        let db = PostgresTelDatabase::new(setup_pool().await);
        // Valid SAI format (E prefix = Blake3-256, 44 chars) that is never inserted
        let digest: said::SelfAddressingIdentifier =
            "EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap();
        let result = db.get_event(&digest).unwrap();
        assert_eq!(result, None);
    }

    #[async_std::test]
    async fn test_missing_issuer_escrow_insert_get_remove() {
        let db = PostgresTelEscrowDatabase::new(setup_pool().await);
        let (vcp, _, _) = parse_tel_events();
        let tel_digest = vcp.event.get_digest().unwrap();
        let kel_digest = "EKel_test_digest_insert_get_remove";

        db.missing_issuer_insert(kel_digest, &tel_digest).unwrap();

        let results = db.missing_issuer_get(kel_digest).unwrap();
        assert!(results.contains(&tel_digest));

        db.missing_issuer_remove(kel_digest, &tel_digest).unwrap();

        let results = db.missing_issuer_get(kel_digest).unwrap();
        assert!(!results.contains(&tel_digest));
    }

    #[async_std::test]
    async fn test_out_of_order_escrow_insert_get_remove() {
        let db = PostgresTelEscrowDatabase::new(setup_pool().await);
        let (_, iss, _) = parse_tel_events();
        let tel_digest = iss.event.get_digest().unwrap();
        let id = iss.event.get_prefix();
        let sn = iss.event.get_sn();

        db.out_of_order_insert(&id, sn, &tel_digest).unwrap();

        let results = db.out_of_order_get(&id, sn).unwrap();
        assert!(results.contains(&tel_digest));

        db.out_of_order_remove(&id, sn, &tel_digest).unwrap();

        let results = db.out_of_order_get(&id, sn).unwrap();
        assert!(!results.contains(&tel_digest));
    }

    #[async_std::test]
    async fn test_missing_registry_escrow_insert_get_remove() {
        let db = PostgresTelEscrowDatabase::new(setup_pool().await);
        let (vcp, _, _) = parse_tel_events();
        let tel_digest = vcp.event.get_digest().unwrap();
        let registry_id = "EPafIvNeW6xYZZhmXBO3hc3GtCHv-8jDgdZsKAFffhLN";

        db.missing_registry_insert(registry_id, &tel_digest).unwrap();

        let results = db.missing_registry_get(registry_id).unwrap();
        assert!(results.contains(&tel_digest));

        db.missing_registry_remove(registry_id, &tel_digest).unwrap();

        let results = db.missing_registry_get(registry_id).unwrap();
        assert!(!results.contains(&tel_digest));
    }
}
