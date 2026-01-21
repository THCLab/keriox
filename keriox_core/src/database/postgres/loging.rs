use crate::{
    database::{postgres::error::PostgresError, LogDatabase as LogDatabaseTrait},
    event_message::signature::{Nontransferable, Transferable},
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
