//! Postgres-backed storage for the SDK.
//!
//! Exercises [`StorageConfig::Postgres`] end to end: identity creation,
//! signing, verification, rotation and reopen, with the key-event databases
//! living in a Postgres server.
//!
//! Requires the `storage-postgres` feature and a reachable Postgres server.
//! Set `DATABASE_URL` to a base connection string, e.g.
//! `postgres://postgres:postgres@localhost:5433/keri_sdk_pg`. When unset the
//! test is skipped so the default suite needs no database.

#![cfg(feature = "storage-postgres")]

use keri_sdk::advanced::types::{IdentifierConfig, StorageConfig};
use keri_sdk::advanced::KeriStore;
use keri_sdk::Keri;

/// The configured Postgres URL, or `None` (test skipped) when `DATABASE_URL`
/// is not set. Drops and recreates the named database so each run is clean.
fn prepare_database() -> Option<String> {
    let url = std::env::var("DATABASE_URL").ok()?;
    let (base, db_name) = url.rsplit_once('/').expect("DATABASE_URL must include a db name");

    async_std::task::block_on(async {
        use sqlx::postgres::PgPoolOptions;
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&format!("{base}/postgres"))
            .await
            .expect("connect to admin database");
        let _ = sqlx::query(&format!(
            "DROP DATABASE IF EXISTS \"{db_name}\" WITH (FORCE)"
        ))
        .execute(&admin)
        .await;
        sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
            .execute(&admin)
            .await
            .expect("create test database");
    });

    Some(url)
}

#[tokio::test(flavor = "multi_thread")]
async fn postgres_identity_lifecycle() {
    let Some(url) = prepare_database() else {
        eprintln!("DATABASE_URL not set — skipping Postgres storage test");
        return;
    };

    let dir = tempfile::tempdir().unwrap();

    // ── advanced layer: KeriStore over Postgres ──────────────────────────
    {
        let store = KeriStore::open_with_storage(
            dir.path().to_path_buf(),
            StorageConfig::Postgres { url: url.clone() },
        )
        .unwrap();

        let (id, signer) = store
            .create("alice", IdentifierConfig::default())
            .await
            .unwrap();
        let envelope =
            keri_sdk::advanced::signing::sign(&id, &signer, b"stored in postgres").unwrap();
        let verified =
            keri_sdk::advanced::signing::verify(&id, envelope.cesr.as_bytes()).unwrap();
        assert_eq!(verified.payload, b"stored in postgres");

        store.rotate("alice").await.unwrap();

        // No event database files on disk — the events are in Postgres.
        // (The query cache and metadata redb still live under the store dir.)
        assert!(!dir.path().join("alice").join("db").exists());
    }

    // ── facade: reopen the same Postgres-backed store ────────────────────
    let keri = Keri::open_with_storage(dir.path(), StorageConfig::Postgres { url }).unwrap();
    let alice = keri.identity("alice").expect("alice persists in postgres");

    // The pre-rotation history is intact, so signing and rotation continue.
    let signed = alice.sign(b"after reopen").await.unwrap();
    assert_eq!(keri.verify(signed.as_cesr()).unwrap().payload, b"after reopen");
    alice.rotate().await.unwrap();
    let again = alice.sign(b"second rotation").await.unwrap();
    assert_eq!(&keri.verify(again.as_cesr()).unwrap().signer, alice.id());
}
