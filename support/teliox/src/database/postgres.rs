use std::path::Path;

use sqlx::{PgPool, Row};

use crate::{
    database::{TelEventDatabase, TelLogDatabase},
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};
use keri_core::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;

pub struct PostgresTelDatabase {
    pool: PgPool,
}

impl PostgresTelDatabase {
    pub fn new_with_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    fn get_from_table(
        &self,
        table: &'static str,
        id: &IdentifierPrefix,
    ) -> Option<Vec<VerifiableEvent>> {
        let id_str = id.to_string();
        async_std::task::block_on(async {
            let query = format!("SELECT digest FROM {table} WHERE identifier = $1 ORDER BY sn ASC");
            let rows = sqlx::query(&query)
                .bind(&id_str)
                .fetch_all(&self.pool)
                .await
                .ok()?;

            let mut events = Vec::new();
            for row in rows {
                let digest: Vec<u8> = row.get("digest");
                let event_row = sqlx::query("SELECT event_data FROM tel_events WHERE digest = $1")
                    .bind(&digest)
                    .fetch_optional(&self.pool)
                    .await
                    .ok()??;

                let bytes: Vec<u8> = event_row.get("event_data");
                let event: VerifiableEvent = serde_cbor::from_slice(&bytes).ok()?;
                events.push(event);
            }

            if events.is_empty() {
                None
            } else {
                Some(events)
            }
        })
    }
}

impl TelEventDatabase for PostgresTelDatabase {
    fn new(_path: impl AsRef<Path>) -> Result<Self, Error>
    where
        Self: Sized,
    {
        Err(Error::Generic(
            "PostgresTelDatabase must be constructed with new_with_pool()".into(),
        ))
    }

    fn add_new_event(&self, event: VerifiableEvent, _id: &IdentifierPrefix) -> Result<(), Error> {
        let digest = event
            .event
            .get_digest()
            .map_err(|_| Error::Generic("Event does not have a digest".into()))?;
        let digest_str = digest.to_string();
        let cbor = serde_cbor::to_vec(&event).map_err(|e| Error::Generic(e.to_string()))?;

        async_std::task::block_on(async {
            let mut tx = self
                .pool
                .begin()
                .await
                .map_err(|e| Error::Generic(e.to_string()))?;

            sqlx::query(
                "INSERT INTO tel_events (digest, event_data) VALUES ($1, $2) \
                 ON CONFLICT (digest) DO NOTHING",
            )
            .bind(&digest_str)
            .bind(&cbor)
            .execute(&mut *tx)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;

            match &event.event {
                Event::Management(m) => {
                    sqlx::query(
                        "INSERT INTO management_tels (identifier, sn, digest) \
                         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    )
                    .bind(m.data.prefix.to_string())
                    .bind(m.data.sn as i64)
                    .bind(&digest_str)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| Error::Generic(e.to_string()))?;
                }
                Event::Vc(v) => {
                    sqlx::query(
                        "INSERT INTO vc_tels (identifier, sn, digest) \
                         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    )
                    .bind(v.data.data.prefix.to_string())
                    .bind(v.data.data.sn as i64)
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
        self.get_from_table("vc_tels", id).map(|v| v.into_iter())
    }

    fn get_management_events(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<impl DoubleEndedIterator<Item = VerifiableEvent>> {
        self.get_from_table("management_tels", id)
            .map(|v| v.into_iter())
    }
}

impl TelLogDatabase for PostgresTelDatabase {
    fn log_event(
        &self,
        event: &VerifiableEvent,
        _transaction: &keri_core::database::redb::WriteTxnMode,
    ) -> Result<(), Error> {
        let digest = event
            .event
            .get_digest()
            .map_err(|_| Error::Generic("Event does not have a digest".into()))?;
        let digest_str = digest.to_string();
        let cbor = serde_cbor::to_vec(event).map_err(|e| Error::Generic(e.to_string()))?;

        async_std::task::block_on(async {
            sqlx::query(
                "INSERT INTO tel_events (digest, event_data) VALUES ($1, $2) \
                 ON CONFLICT (digest) DO NOTHING",
            )
            .bind(&digest_str)
            .bind(&cbor)
            .execute(&self.pool)
            .await
            .map_err(|e| Error::Generic(e.to_string()))?;
            Ok(())
        })
    }

    fn get(&self, digest: &SelfAddressingIdentifier) -> Result<Option<VerifiableEvent>, Error> {
        let digest_str = digest.to_string();
        async_std::task::block_on(async {
            let row = sqlx::query("SELECT event_data FROM tel_events WHERE digest = $1")
                .bind(&digest_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| Error::Generic(e.to_string()))?;

            match row {
                Some(row) => {
                    let bytes: Vec<u8> = row.get("event_data");
                    let event: VerifiableEvent = serde_cbor::from_slice(&bytes)
                        .map_err(|e| Error::Generic(e.to_string()))?;
                    Ok(Some(event))
                }
                None => Ok(None),
            }
        })
    }
}
