use std::sync::Arc;

use said::SelfAddressingIdentifier;
use sqlx::{PgPool, Row};

use crate::{
    database::{
        postgres::error::PostgresError,
        rkyv_adapter,
    },
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
};

pub struct KsnLogDatabase {
    pool: PgPool,
}

pub struct AcceptedKsn {
    ksn_log: Arc<KsnLogDatabase>,
    pool: PgPool,
}

impl AcceptedKsn {
    pub fn new(pool: PgPool) -> Self {
        let ksn_log = Arc::new(KsnLogDatabase::new(pool.clone()));
        Self { ksn_log, pool }
    }

    pub fn insert(&self, reply: SignedReply) -> Result<(), PostgresError> {
        let (from_who, about_who) = match reply.reply.get_route() {
            ReplyRoute::Ksn(id, ksn) => (id, ksn.state.prefix),
            _ => panic!("Wrong event type"),
        };

        let digest = reply
            .reply
            .digest()
            .map_err(|_| PostgresError::MissingDigest)?;
        let serialized_digest = rkyv_adapter::serialize_said(&digest)?;

        async_std::task::block_on(async {
            let mut tx = self.pool.begin().await?;

            // Store the KSN event itself
            let value = serde_cbor::to_vec(&reply).unwrap();
            sqlx::query(
                "INSERT INTO ksns (digest, ksn_data) VALUES ($1, $2) \
                   ON CONFLICT (digest) DO NOTHING",
            )
            .bind(serialized_digest.as_ref())
            .bind(value.as_slice())
            .execute(&mut *tx)
            .await?;

            // Update the accepted index
            sqlx::query(
                "INSERT INTO accepted_ksns (about_who, from_who, digest) VALUES ($1, $2, $3) \
                   ON CONFLICT (about_who, from_who) DO UPDATE SET digest = $3",
            )
            .bind(about_who.to_string())
            .bind(from_who.to_string())
            .bind(serialized_digest.as_ref())
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok(())
        })
    }

    pub fn get_all(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, PostgresError> {
        async_std::task::block_on(async {
            let rows = sqlx::query("SELECT digest FROM accepted_ksns WHERE about_who = $1")
                .bind(id.to_string())
                .fetch_all(&self.pool)
                .await?;

            let mut replies = Vec::new();
            for row in rows {
                let digest_bytes: Vec<u8> = row.get("digest");
                let said = rkyv_adapter::deserialize_said(&digest_bytes)?;
                if let Some(reply) = self.ksn_log.get_signed_reply(&said)? {
                    replies.push(reply);
                }
            }
            Ok(replies)
        })
    }

    pub fn get(
        &self,
        id: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
    ) -> Result<Option<SignedReply>, PostgresError> {
        async_std::task::block_on(async {
            let row = sqlx::query(
                "SELECT digest FROM accepted_ksns WHERE about_who = $1 AND from_who = $2",
            )
            .bind(id.to_string())
            .bind(from_who.to_string())
            .fetch_optional(&self.pool)
            .await?;

            match row {
                Some(row) => {
                    let digest_bytes: Vec<u8> = row.get("digest");
                    let said = rkyv_adapter::deserialize_said(&digest_bytes)?;
                    self.ksn_log.get_signed_reply(&said)
                }
                None => Ok(None),
            }
        })
    }
}

impl KsnLogDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn get_signed_reply(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedReply>, PostgresError> {
        let key = rkyv_adapter::serialize_said(said)?;

        async_std::task::block_on(async {
            let row = sqlx::query("SELECT ksn_data FROM ksns WHERE digest = $1")
                .bind(key.as_ref())
                .fetch_optional(&self.pool)
                .await?;

            match row {
                Some(row) => {
                    let bytes: Vec<u8> = row.get("ksn_data");
                    let reply: SignedReply = serde_cbor::from_slice(&bytes).unwrap();
                    Ok(Some(reply))
                }
                None => Ok(None),
            }
        })
    }
}
