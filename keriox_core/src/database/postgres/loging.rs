use crate::{
    database::{
        postgres::error::PostgresError, rkyv_adapter, timestamped::TimestampedSignedEventMessage,
        LogDatabase as LogDatabaseTrait,
    },
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::SignedEventMessage,
    },
    prefix::IndexedSignature,
};

use rkyv::{
    api::high::HighSerializer, rancor::Failure, ser::allocator::ArenaHandle, util::AlignedVec,
};
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
    pub async fn log_event_with_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        signed_event: &SignedEventMessage,
    ) -> Result<(), PostgresError> {
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

    pub(super) fn get_nontrans_couplets_by_key(
        &self,
        key: &[u8],
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, PostgresError> {
        async_std::task::block_on(async {
            let rows = sqlx::query("SELECT receipt_data FROM nontrans_receipts WHERE digest = $1")
                .bind(key)
                .fetch_all(&self.pool)
                .await?;

            let nontrans = rows
                .into_iter()
                .map(|row| {
                    let bytes: Vec<u8> = row.get("receipt_data");
                    rkyv_adapter::deserialize_nontransferable(&bytes).map_err(PostgresError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(if nontrans.is_empty() {
                None
            } else {
                Some(nontrans.into_iter())
            })
        })
    }

    fn get_trans_receipts_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, PostgresError> {
        async_std::task::block_on(async {
            let rows = sqlx::query("SELECT receipt_data FROM trans_receipts WHERE digest = $1")
                .bind(key)
                .fetch_all(&self.pool)
                .await?;

            let trans = rows
                .into_iter()
                .map(|row| {
                    let bytes: Vec<u8> = row.get("receipt_data");
                    rkyv_adapter::deserialize_transferable(&bytes).map_err(PostgresError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(trans.into_iter())
        })
    }

    fn get_event_by_serialized_key(
        &self,
        as_slice: &[u8],
    ) -> Result<Option<KeriEvent<KeyEvent>>, PostgresError> {
        async_std::task::block_on(async {
            let row = sqlx::query("SELECT event_data FROM events WHERE digest = $1")
                .bind(as_slice)
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(row) => {
                    let bytes: Vec<u8> = row.get("event_data");
                    let event = rkyv::from_bytes::<_, Failure>(&bytes).unwrap();
                    Ok(Some(event))
                }
                None => Ok(None),
            }
        })
    }

    fn get_signatures_by_serialized_key(
        &self,
        key: &[u8],
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, PostgresError> {
        async_std::task::block_on(async {
            let rows = sqlx::query("SELECT signature_data FROM signatures WHERE digest = $1")
                .bind(key)
                .fetch_all(&self.pool)
                .await?;

            let sigs = rows
                .into_iter()
                .map(|row| {
                    let bytes: Vec<u8> = row.get("signature_data");
                    rkyv_adapter::deserialize_indexed_signatures(&bytes)
                        .map_err(PostgresError::from)
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(if sigs.is_empty() {
                None
            } else {
                Some(sigs.into_iter())
            })
        })
    }
}

impl<'db> LogDatabaseTrait<'db> for PostgresLogDatabase {
    type DatabaseType = PgPool;
    type Error = PostgresError;
    type TransactionType = PostgresWriteTxnMode;

    fn new(db: std::sync::Arc<Self::DatabaseType>) -> Result<Self, PostgresError>
    where
        Self: Sized,
    {
        Ok(Self {
            pool: (*db).clone(),
        })
    }

    fn log_event(
        &self,
        txn: &Self::TransactionType,
        signed_event: &SignedEventMessage,
    ) -> Result<(), Self::Error> {
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
        let digest = &signed_receipt.body.receipted_event_digest;
        self.insert_nontrans_receipt(digest, &signed_receipt.signatures)?;
        Ok(())
    }

    fn log_receipt_with_new_transaction(
        &self,
        signed_receipt: &crate::event_message::signed_event_message::SignedNontransferableReceipt,
    ) -> Result<(), Self::Error> {
        self.log_receipt(&PostgresWriteTxnMode::CreateNew, signed_receipt)
    }

    fn get_signed_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<TimestampedSignedEventMessage>, Self::Error> {
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
            let event: KeriEvent<KeyEvent> = rkyv::from_bytes::<_, Failure>(&event_bytes).unwrap();

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
    ) -> Result<Option<KeriEvent<KeyEvent>>, Self::Error> {
        let key = rkyv_adapter::serialize_said(said)?;
        self.get_event_by_serialized_key(key.as_slice())
    }

    fn get_signatures(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = IndexedSignature>>, PostgresError> {
        let key = rkyv_adapter::serialize_said(said)?;
        self.get_signatures_by_serialized_key(key.as_ref())
    }

    fn get_nontrans_couplets(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<impl Iterator<Item = Nontransferable>>, PostgresError> {
        let serialized_said = rkyv_adapter::serialize_said(said)?;
        self.get_nontrans_couplets_by_key(serialized_said.as_ref())
    }

    fn get_trans_receipts(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<impl DoubleEndedIterator<Item = Transferable>, PostgresError> {
        let key = rkyv_adapter::serialize_said(said)?;
        self.get_trans_receipts_by_serialized_key(key.as_slice())
    }

    fn remove_nontrans_receipt(
        &self,
        txn_mode: &Self::TransactionType,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), Self::Error> {
        async_std::task::block_on(async {
            let serialized_said = rkyv_adapter::serialize_said(said)?;

            let receipt_bytes: Result<Vec<Vec<u8>>, _> = nontrans
                .into_iter()
                .map(|receipt| {
                    rkyv::to_bytes::<rkyv::rancor::Error>(&receipt)
                        .map(|b| b.to_vec())
                        .map_err(PostgresError::from)
                })
                .collect();
            let receipt_bytes = receipt_bytes?;

            if !receipt_bytes.is_empty() {
                let receipt_refs: Vec<&[u8]> = receipt_bytes.iter().map(Vec::as_slice).collect();
                sqlx::query(
                    "DELETE FROM nontrans_receipts WHERE digest = $1 AND receipt_data = ANY($2)",
                )
                .bind(serialized_said.as_ref())
                .bind(receipt_refs.as_slice())
                .execute(&self.pool)
                .await?;
            }
            Ok(())
        })
    }

    fn remove_nontrans_receipt_with_new_transaction(
        &self,
        said: &said::SelfAddressingIdentifier,
        nontrans: impl IntoIterator<Item = Nontransferable>,
    ) -> Result<(), PostgresError> {
        self.remove_nontrans_receipt(&PostgresWriteTxnMode::CreateNew, said, nontrans)
    }
}
