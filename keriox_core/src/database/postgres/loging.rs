use crate::{
    database::{postgres::error::PostgresError, LogDatabase as LogDatabaseTrait},
    event::KeyEvent,
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Transferable},
        signed_event_message::SignedEventMessage,
    },
    prefix::IndexedSignature,
};

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

    /// Async: log a signed event (stores event + signatures + receipts)
    pub async fn log_event_async(
        &self,
        signed_event: &SignedEventMessage,
    ) -> Result<(), PostgresError> {
        // 1. Insert the event
        self.insert_key_event_async(&signed_event.event_message)
            .await?;

        // 2. Insert signatures
        let digest = signed_event
            .event_message
            .digest()
            .map_err(|_e| PostgresError::MissingDigest)?;

        self.insert_indexed_signatures_async(&digest, &signed_event.signatures)
            .await?;

        // 3. Insert witness receipts if present
        if let Some(wits) = &signed_event.witness_receipts {
            self.insert_nontrans_receipt_async(&digest, wits).await?;
        }

        Ok(())
    }

    /// Async: insert a key event into the events table
    async fn insert_key_event_async(
        &self,
        event: &KeriEvent<KeyEvent>,
    ) -> Result<(), PostgresError> {
        let digest = event.digest().map_err(|_e| PostgresError::MissingDigest)?;
        let key = rkyv::to_bytes::<rkyv::rancor::Error>(&digest)?;
        let value = rkyv::to_bytes::<rkyv::rancor::Error>(event)?;

        sqlx::query(
            "INSERT INTO events (digest, event_data) VALUES ($1, $2)
             ON CONFLICT (digest) DO NOTHING",
        )
        .bind(key.as_slice())
        .bind(value.as_slice())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Async: insert indexed signatures
    async fn insert_indexed_signatures_async(
        &self,
        said: &said::SelfAddressingIdentifier,
        signatures: &[IndexedSignature],
    ) -> Result<(), PostgresError> {
        let serialized_said = rkyv::to_bytes::<rkyv::rancor::Error>(said)?;

        for sig in signatures {
            let sig_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(sig)?;
            sqlx::query(
                "INSERT INTO signatures (digest, signature_data) VALUES ($1, $2)
                 ON CONFLICT (digest, signature_data) DO NOTHING",
            )
            .bind(serialized_said.as_slice())
            .bind(sig_bytes.as_slice())
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Async: insert non-transferable receipts
    async fn insert_nontrans_receipt_async(
        &self,
        said: &said::SelfAddressingIdentifier,
        nontrans: &[Nontransferable],
    ) -> Result<(), PostgresError> {
        let serialized_said = rkyv::to_bytes::<rkyv::rancor::Error>(said)?;

        for receipt in nontrans {
            let receipt_bytes = rkyv::to_bytes::<rkyv::rancor::Error>(receipt)?;
            sqlx::query(
                "INSERT INTO nontrans_receipts (digest, receipt_data) VALUES ($1, $2)
                 ON CONFLICT (digest, receipt_data) DO NOTHING",
            )
            .bind(serialized_said.as_slice())
            .bind(receipt_bytes.as_slice())
            .execute(&self.pool)
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
        signed_event: &crate::event_message::signed_event_message::SignedEventMessage,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn log_event_with_new_transaction(
        &self,
        signed_event: &crate::event_message::signed_event_message::SignedEventMessage,
    ) -> Result<(), Self::Error> {
        todo!()
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
        todo!()
    }

    fn get_event(
        &self,
        said: &said::SelfAddressingIdentifier,
    ) -> Result<Option<crate::event_message::msg::KeriEvent<crate::event::KeyEvent>>, Self::Error>
    {
        todo!()
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
