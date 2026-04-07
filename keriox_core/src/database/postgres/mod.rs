use std::sync::Arc;

use cesrox::primitives::CesrPrimitive;
use said::{sad::SerializationFormats, SelfAddressingIdentifier};
use sqlx::{postgres::PgPoolOptions, PgPool, Row};

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;
use crate::{
    database::{postgres::error::PostgresError, rkyv_adapter, EventDatabase, LogDatabase},
    event::{receipt::Receipt, KeyEvent},
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::{
            SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
        },
    },
    prefix::IdentifierPrefix,
    state::IdentifierState,
};

#[cfg(feature = "query")]
use ksn_log::AcceptedKsn;

mod error;
mod escrow_database;
#[cfg(feature = "query")]
mod ksn_log;
mod loging;
#[cfg(feature = "oobi-manager")]
pub mod oobi_storage;

pub use loging::PostgresLogDatabase;
#[cfg(feature = "oobi-manager")]
pub use oobi_storage::PostgresOobiStorage;

use super::{timestamped::TimestampedSignedEventMessage, QueryParameters};

/// Configuration for the PostgreSQL connection pool.
pub struct PostgresConfig {
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
}

impl Default for PostgresConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
        }
    }
}

pub struct PostgresDatabase {
    pub pool: PgPool,
    pub(crate) log_db: Arc<PostgresLogDatabase>,
    #[cfg(feature = "query")]
    accepted_rpy: Arc<AcceptedKsn>,
}

impl PostgresDatabase {
    pub async fn new(database_url: &str) -> Result<Self, PostgresError> {
        Self::new_with_config(database_url, PostgresConfig::default()).await
    }

    pub async fn new_with_config(
        database_url: &str,
        config: PostgresConfig,
    ) -> Result<Self, PostgresError> {
        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .connect(database_url)
            .await?;

        let log_db = Arc::new(PostgresLogDatabase::new(pool.clone()));

        #[cfg(feature = "query")]
        let accepted_rpy = Arc::new(AcceptedKsn::new(pool.clone()));

        Ok(Self {
            pool,
            log_db,
            #[cfg(feature = "query")]
            accepted_rpy,
        })
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
        event: &KeriEvent<KeyEvent>,
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

    fn get_event_digest(
        &self,
        identifier: &IdentifierPrefix,
        sn: u64,
    ) -> Result<Option<SelfAddressingIdentifier>, PostgresError> {
        async_std::task::block_on(async {
            let row = sqlx::query("SELECT digest FROM kels WHERE identifier = $1 AND sn = $2")
                .bind(identifier.to_str())
                .bind(sn as i64)
                .fetch_optional(&self.pool)
                .await?;

            if let Some(row) = row {
                let digest_bytes: Vec<u8> = row.get("digest");
                let digest = rkyv_adapter::deserialize_said(&digest_bytes)?;
                Ok(Some(digest))
            } else {
                Ok(None)
            }
        })
    }

    fn get_nontrans_receipts_range(
        &self,
        id: &str,
        start: u64,
        limit: u64,
    ) -> Result<Vec<SignedNontransferableReceipt>, PostgresError> {
        async_std::task::block_on(async {
            let rows = if limit == u64::MAX {
                sqlx::query(
                    "SELECT k.sn, k.digest, nr.receipt_data \
                     FROM kels k \
                     LEFT JOIN nontrans_receipts nr ON k.digest = nr.digest \
                     WHERE k.identifier = $1 AND k.sn >= $2 \
                     ORDER BY k.sn ASC",
                )
                .bind(id)
                .bind(start as i64)
                .fetch_all(&self.pool)
                .await?
            } else {
                let end_sn = start.saturating_add(limit) as i64;
                sqlx::query(
                    "SELECT k.sn, k.digest, nr.receipt_data \
                     FROM kels k \
                     LEFT JOIN nontrans_receipts nr ON k.digest = nr.digest \
                     WHERE k.identifier = $1 AND k.sn >= $2 AND k.sn < $3 \
                     ORDER BY k.sn ASC",
                )
                .bind(id)
                .bind(start as i64)
                .bind(end_sn)
                .fetch_all(&self.pool)
                .await?
            };

            let mut grouped: std::collections::BTreeMap<u64, (Vec<u8>, Vec<Nontransferable>)> =
                std::collections::BTreeMap::new();

            for row in rows {
                let sn: i64 = row.get("sn");
                let digest_bytes: Vec<u8> = row.get("digest");
                let receipt_data: Option<Vec<u8>> = row.get("receipt_data");

                let entry = grouped
                    .entry(sn as u64)
                    .or_insert_with(|| (digest_bytes, Vec::new()));

                if let Some(bytes) = receipt_data {
                    if let Ok(nt) = rkyv_adapter::deserialize_nontransferable(&bytes) {
                        entry.1.push(nt);
                    }
                }
            }

            let identifier: IdentifierPrefix = id.parse().unwrap();
            let receipts = grouped
                .into_iter()
                .map(|(sn, (digest_bytes, nontrans))| {
                    let said = rkyv_adapter::deserialize_said(&digest_bytes).unwrap();
                    let rct =
                        Receipt::new(SerializationFormats::JSON, said, identifier.clone(), sn);
                    SignedNontransferableReceipt {
                        body: rct,
                        signatures: nontrans,
                    }
                })
                .collect();

            Ok(receipts)
        })
    }

    async fn save_to_kel(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        event: &KeriEvent<KeyEvent>,
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

impl EventDatabase for PostgresDatabase {
    type Error = PostgresError;
    type LogDatabaseType = PostgresLogDatabase;

    fn get_log_db(&self) -> Arc<Self::LogDatabaseType> {
        self.log_db.clone()
    }

    fn add_kel_finalized_event(
        &self,
        signed_event: SignedEventMessage,
        _id: &IdentifierPrefix,
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
        receipt: SignedTransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let digest = receipt.body.receipted_event_digest;
        let transferable = Transferable::Seal(receipt.validator_seal, receipt.signatures);
        self.log_db.insert_trans_receipt(&digest, &[transferable])
    }

    fn add_receipt_nt(
        &self,
        receipt: SignedNontransferableReceipt,
        _id: &IdentifierPrefix,
    ) -> Result<(), Self::Error> {
        let receipted_event_digest = receipt.body.receipted_event_digest;
        let receipts = receipt.signatures;
        self.log_db
            .insert_nontrans_receipt(&receipted_event_digest, &receipts)
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
    ) -> Option<impl DoubleEndedIterator<Item = Transferable>> {
        match params {
            QueryParameters::BySn { id, sn } => {
                if let Ok(Some(said)) = self.get_event_digest(&id, sn) {
                    let receipts = self.log_db.get_trans_receipts(&said).ok()?;
                    Some(receipts.collect::<Vec<_>>().into_iter())
                } else {
                    None
                }
            }
            QueryParameters::Range { .. } => todo!(),
            QueryParameters::All { .. } => todo!(),
        }
    }

    fn get_receipts_nt(
        &self,
        params: QueryParameters,
    ) -> Option<impl DoubleEndedIterator<Item = SignedNontransferableReceipt>> {
        match params {
            QueryParameters::BySn { id, sn } => self
                .get_nontrans_receipts_range(&id.to_str(), sn, 1)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::Range { id, start, limit } => self
                .get_nontrans_receipts_range(&id.to_str(), start, limit)
                .ok()
                .map(|e| e.into_iter()),
            QueryParameters::All { id } => self
                .get_nontrans_receipts_range(&id.to_str(), 0, u64::MAX)
                .ok()
                .map(|e| e.into_iter()),
        }
    }

    fn accept_to_kel(&self, event: &KeriEvent<KeyEvent>) -> Result<(), Self::Error> {
        async_std::task::block_on(async {
            let mut tx = self.pool.begin().await?;

            self.update_key_state(&mut tx, event).await?;
            self.save_to_kel(&mut tx, event).await?;

            tx.commit().await?;
            Ok(())
        })
    }

    #[cfg(feature = "query")]
    fn save_reply(&self, reply: SignedReply) -> Result<(), Self::Error> {
        self.accepted_rpy.insert(reply)
    }

    #[cfg(feature = "query")]
    fn get_reply(&self, id: &IdentifierPrefix, from_who: &IdentifierPrefix) -> Option<SignedReply> {
        self.accepted_rpy.get(id, from_who).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        actor::event_generator,
        database::QueryParameters,
        event_message::{
            cesr_adapter::{parse_event_type, EventType},
            EventTypeTag,
        },
        prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
        signer::{CryptoBox, KeyManager},
    };

    fn get_database_url() -> String {
        std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/keri_test".to_string())
    }

    async fn setup_db() -> Arc<PostgresDatabase> {
        let db = Arc::new(
            PostgresDatabase::new(&get_database_url())
                .await
                .expect("Failed to connect to database"),
        );
        db.run_migrations().await.expect("Failed to run migrations");
        db
    }

    fn make_signed_icp() -> (
        crate::prefix::IdentifierPrefix,
        crate::event_message::signed_event_message::SignedEventMessage,
    ) {
        let key_manager = CryptoBox::new().unwrap();
        let pk = BasicPrefix::Ed25519(key_manager.public_key());
        let npk = BasicPrefix::Ed25519(key_manager.next_public_key());

        let icp_str = event_generator::incept(vec![pk], vec![npk], vec![], 0, None).unwrap();
        let sig = SelfSigningPrefix::Ed25519Sha512(key_manager.sign(icp_str.as_bytes()).unwrap());
        let ke = match parse_event_type(icp_str.as_bytes()).unwrap() {
            EventType::KeyEvent(ke) => ke,
            _ => panic!("Expected key event"),
        };
        let signed = ke.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None);
        let prefix = signed.event_message.data.get_prefix();
        (prefix, signed)
    }

    #[async_std::test]
    #[ignore]
    async fn test_postgres_migrations() {
        setup_db().await;
        println!("Migrations completed successfully!");
    }

    #[async_std::test]
    #[ignore]
    async fn test_postgres_incept() {
        let db = setup_db().await;
        let (prefix, signed_event) = make_signed_icp();

        db.add_kel_finalized_event(signed_event, &prefix)
            .expect("Failed to store inception event");

        let state = db
            .get_key_state(&prefix)
            .expect("State should exist after inception");
        assert_eq!(state.sn, 0);
    }

    #[async_std::test]
    #[ignore]
    async fn test_postgres_get_kel() {
        let db = setup_db().await;
        let (prefix, signed_event) = make_signed_icp();

        db.add_kel_finalized_event(signed_event, &prefix)
            .expect("Failed to store inception event");

        let kel = db.get_kel(&prefix, 0, 1).expect("get_kel failed");
        assert_eq!(kel.len(), 1);
        assert_eq!(
            kel[0].signed_event_message.event_message.event_type,
            EventTypeTag::Icp
        );

        let full: Vec<_> = db
            .get_kel_finalized_events(QueryParameters::All { id: &prefix })
            .expect("Full KEL should exist")
            .collect();
        assert_eq!(full.len(), 1);

        let by_sn: Vec<_> = db
            .get_kel_finalized_events(QueryParameters::BySn {
                id: prefix.clone(),
                sn: 0,
            })
            .expect("BySn should return event")
            .collect();
        assert_eq!(by_sn.len(), 1);

        assert!(db
            .get_kel_finalized_events(QueryParameters::BySn {
                id: prefix.clone(),
                sn: 99
            })
            .is_none());
    }
}
