use crate::{
    database::{
        postgres::error::PostgresError, redb::rkyv_adapter, LogDatabase as LogDatabaseTrait,
    },
    event_message::{
        signature::{Nontransferable, Transferable},
        signed_event_message::SignedEventMessage,
    },
    prefix::IndexedSignature,
};

use rkyv::{api::high::HighSerializer, ser::allocator::ArenaHandle, util::AlignedVec};
use said::SelfAddressingIdentifier;
use sqlx::{PgPool, Row};

pub struct PostgresLogDatabase {
    pool: PgPool,
}

/// Transaction mode for PostgreSQL operations
pub enum PostgresWriteTxnMode {
    /// Create a new transaction
    CreateNew,
    /// Operations are executed without explicit transaction management
    /// (caller is responsible for transaction handling)
    NoTransaction,
}

impl PostgresLogDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    fn insert_with_digest_key<
        V: for<'a> rkyv::Serialize<HighSerializer<AlignedVec, ArenaHandle<'a>, rkyv::rancor::Error>>,
    >(
        &self,
        table: &str,
        value_column: &str,
        said: &SelfAddressingIdentifier,
        values: &[V],
    ) -> Result<(), PostgresError> {
        let serialized_said = rkyv_adapter::serialize_said(said)?;
        let query = format!(
            "INSERT INTO {table} (digest, {value_column}) VALUES ($1, $2) \
             ON CONFLICT (digest, {value_column}) DO NOTHING"
        );

        async_std::task::block_on(async {
            let mut tx = self.pool.begin().await?;

            for value in values {
                let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(value)?;
                sqlx::query(&query)
                    .bind(serialized_said.as_ref())
                    .bind(bytes.as_ref())
                    .execute(&mut *tx)
                    .await?;
            }

            tx.commit().await?;
            Ok(())
        })
    }

    pub(super) fn insert_nontrans_receipt(
        &self,
        said: &SelfAddressingIdentifier,
        nontrans: &[Nontransferable],
    ) -> Result<(), PostgresError> {
        self.insert_with_digest_key("nontrans_receipts", "receipt_data", said, nontrans)
    }

    pub(super) fn insert_trans_receipt(
        &self,
        said: &SelfAddressingIdentifier,
        trans: &[Transferable],
    ) -> Result<(), PostgresError> {
        self.insert_with_digest_key("trans_receipts", "receipt_data", said, trans)
    }

    /// Workaround: The `LogDatabase` trait takes `&Self::TransactionType` (immutable),
    /// which prevents passing a `&mut sqlx::Transaction` through the trait's `log_event`.
    /// This async method accepts an existing transaction directly so callers like
    /// `add_kel_finalized_event` can log events within the same transaction.
    /// TODO: Consider changing the trait to take `&mut Self::TransactionType` so this
    /// can be unified with `log_event`.
    pub async fn log_event_with_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        signed_event: &SignedEventMessage,
    ) -> Result<(), PostgresError> {
        use crate::database::redb::rkyv_adapter;

        let digest = signed_event
            .event_message
            .digest()
            .map_err(|_| PostgresError::MissingDigest)?;
        let serialized_digest = rkyv_adapter::serialize_said(&digest)?;

        // 1. Store the event (digest -> event_data)
        let event_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&signed_event.event_message)?;
        sqlx::query(
            "INSERT INTO events (digest, event_data) VALUES ($1, $2) \
             ON CONFLICT (digest) DO NOTHING",
        )
        .bind(serialized_digest.as_ref())
        .bind(event_bytes.as_ref())
        .execute(&mut **tx)
        .await?;

        // 2. Store signatures (digest -> signature_data)
        for sig in &signed_event.signatures {
            let sig_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(sig)?;
            sqlx::query(
                "INSERT INTO signatures (digest, signature_data) VALUES ($1, $2) \
                 ON CONFLICT (digest, signature_data) DO NOTHING",
            )
            .bind(serialized_digest.as_ref())
            .bind(sig_bytes.as_ref())
            .execute(&mut **tx)
            .await?;
        }

        // 3. Store witness receipts (nontransferable)
        if let Some(receipts) = &signed_event.witness_receipts {
            for receipt in receipts {
                let receipt_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(receipt)?;
                sqlx::query(
                    "INSERT INTO nontrans_receipts (digest, receipt_data) VALUES ($1, $2) \
                     ON CONFLICT (digest, receipt_data) DO NOTHING",
                )
                .bind(serialized_digest.as_ref())
                .bind(receipt_bytes.as_ref())
                .execute(&mut **tx)
                .await?;
            }
        }

        // 4. Store delegator seal
        if let Some(seal) = &signed_event.delegator_seal {
            let seal_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(seal)?;
            sqlx::query(
                "INSERT INTO seals (digest, seal_data) VALUES ($1, $2) \
                 ON CONFLICT (digest) DO NOTHING",
            )
            .bind(serialized_digest.as_ref())
            .bind(seal_bytes.as_ref())
            .execute(&mut **tx)
            .await?;
        }

        Ok(())
    }
}
//TODO: provide sync wrapper around the async methods using block_in_place ??
impl<'db> LogDatabaseTrait<'db> for PostgresLogDatabase {
    type DatabaseType = PgPool;
    type Error = PostgresError;
    type TransactionType = PostgresWriteTxnMode;

    fn new(db: std::sync::Arc<Self::DatabaseType>) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        todo!()
    }

    fn log_event(
        &self,
        txn: &Self::TransactionType,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        use crate::database::redb::rkyv_adapter;

        let digest = signed_event
            .event_message
            .digest()
            .map_err(|_| PostgresError::MissingDigest)?;
        let serialized_digest = rkyv_adapter::serialize_said(&digest)?;

        // 1. Store the event (digest -> event_data)
        let event_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&signed_event.event_message)?;
        async_std::task::block_on(async {
            sqlx::query(
                "INSERT INTO events (digest, event_data) VALUES ($1, $2) \
                     ON CONFLICT (digest) DO NOTHING",
            )
            .bind(serialized_digest.as_ref())
            .bind(event_bytes.as_ref())
            .execute(&self.pool)
            .await?;

            // 2. Store signatures (digest -> signature_data)
            for sig in &signed_event.signatures {
                let sig_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(sig)?;
                sqlx::query(
                    "INSERT INTO signatures (digest, signature_data) VALUES ($1, $2) \
                         ON CONFLICT (digest, signature_data) DO NOTHING",
                )
                .bind(serialized_digest.as_ref())
                .bind(sig_bytes.as_ref())
                .execute(&self.pool)
                .await?;
            }

            // 3. Store witness receipts (nontransferable)
            if let Some(receipts) = &signed_event.witness_receipts {
                for receipt in receipts {
                    let receipt_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(receipt)?;
                    sqlx::query(
                        "INSERT INTO nontrans_receipts (digest, receipt_data) VALUES ($1, $2) \
                             ON CONFLICT (digest, receipt_data) DO NOTHING",
                    )
                    .bind(serialized_digest.as_ref())
                    .bind(receipt_bytes.as_ref())
                    .execute(&self.pool)
                    .await?;
                }
            }

            // 4. Store delegator seal
            if let Some(seal) = &signed_event.delegator_seal {
                let seal_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(seal)?;
                sqlx::query(
                    "INSERT INTO seals (digest, seal_data) VALUES ($1, $2) \
                         ON CONFLICT (digest) DO NOTHING",
                )
                .bind(serialized_digest.as_ref())
                .bind(seal_bytes.as_ref())
                .execute(&self.pool)
                .await?;
            }
            Ok(())
        })
    }

    fn log_event_with_new_transaction(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
        self.log_event(&PostgresWriteTxnMode::CreateNew, signed_event)
    }

    fn log_receipt(
        &self,
        txn: &Self::TransactionType,
        signed_receipt: &crate::event_message::signed_event_message::SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn log_receipt_with_new_transaction(
        &self,
        signed_receipt: &crate::event_message::signed_event_message::SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn get_signed_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<crate::database::timestamped::TimestampedSignedEventMessage>, Self::Error>
    {
        use crate::database::redb::rkyv_adapter;
        use crate::database::timestamped::TimestampedSignedEventMessage;
        use crate::event_message::signed_event_message::SignedEventMessage;

        let key = rkyv_adapter::serialize_said(said)?;

        async_std::task::block_on(async {
            // 1. Fetch event
            let event_row = sqlx::query("SELECT event_data FROM events WHERE digest = $1")
                .bind(key.as_ref())
                .fetch_optional(&self.pool)
                .await?;

            let event_row = match event_row {
                Some(row) => row,
                None => return Ok(None),
            };

            let event_bytes: Vec<u8> = event_row.get("event_data");
            let event: crate::event_message::msg::KeriEvent<crate::event::KeyEvent> =
                rkyv::from_bytes::<_, rkyv::rancor::Failure>(&event_bytes).unwrap();

            // 2. Fetch signatures
            let sig_rows = sqlx::query("SELECT signature_data FROM signatures WHERE digest = $1")
                .bind(key.as_ref())
                .fetch_all(&self.pool)
                .await?;

            let signatures: Vec<IndexedSignature> = sig_rows
                .iter()
                .filter_map(|row| {
                    let bytes: Vec<u8> = row.get("signature_data");
                    rkyv_adapter::deserialize_indexed_signatures(&bytes).ok()
                })
                .collect();

            // 3. Fetch nontransferable receipts
            let receipt_rows =
                sqlx::query("SELECT receipt_data FROM nontrans_receipts WHERE digest = $1")
                    .bind(key.as_ref())
                    .fetch_all(&self.pool)
                    .await?;

            let receipts: Vec<Nontransferable> = receipt_rows
                .iter()
                .filter_map(|row| {
                    let bytes: Vec<u8> = row.get("receipt_data");
                    rkyv_adapter::deserialize_nontransferable(&bytes).ok()
                })
                .collect();

            let witness_receipts = if receipts.is_empty() {
                None
            } else {
                Some(receipts)
            };

            // 4. Fetch delegator seal
            let seal_row = sqlx::query("SELECT seal_data FROM seals WHERE digest = $1")
                .bind(key.as_ref())
                .fetch_optional(&self.pool)
                .await?;

            let delegator_seal = seal_row.and_then(|row| {
                let bytes: Vec<u8> = row.get("seal_data");
                rkyv_adapter::deserialize_source_seal(&bytes).ok()
            });

            Ok(Some(TimestampedSignedEventMessage::new(
                SignedEventMessage::new(&event, signatures, witness_receipts, delegator_seal),
            )))
        })
    }

    fn get_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<crate::event_message::msg::KeriEvent<crate::event::KeyEvent>>, Self::Error>
    {
        use crate::database::redb::rkyv_adapter;

        let key = rkyv_adapter::serialize_said(said)?;

        async_std::task::block_on(async {
            let row = sqlx::query("SELECT event_data FROM events WHERE digest = $1")
                .bind(key.as_ref())
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(row) => {
                    let bytes: Vec<u8> = row.get("event_data");
                    let event = rkyv::from_bytes::<_, rkyv::rancor::Failure>(&bytes).unwrap();
                    Ok(Some(event))
                }
                None => Ok(None),
            }
        })
    }

    fn get_signatures(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, Self::Error> {
        Ok(None::<std::vec::IntoIter<IndexedSignature>>)
    }

    fn get_nontrans_couplets(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, Self::Error> {
        Ok(None::<std::vec::IntoIter<Nontransferable>>)
    }

    fn get_trans_receipts(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, Self::Error> {
        Ok(Vec::<Transferable>::new().into_iter())
    }

    fn remove_nontrans_receipt(
        &self,
        txn_mode: &Self::TransactionType,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn remove_nontrans_receipt_with_new_transaction(
        &self,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
