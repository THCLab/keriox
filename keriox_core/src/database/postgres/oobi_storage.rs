use super::error::PostgresError;
use crate::oobi::{Role, Scheme};
use crate::oobi_manager::storage::OobiStorageBackend;
use crate::prefix::IdentifierPrefix;
use crate::query::reply_event::{ReplyRoute, SignedReply};
use sqlx::PgPool;

pub struct PostgresOobiStorage {
    pool: PgPool,
}

impl PostgresOobiStorage {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl OobiStorageBackend for PostgresOobiStorage {
    type Error = PostgresError;

    fn get_oobis_for_eid(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, Self::Error> {
        async_std::task::block_on(async {
            let rows: Vec<(Vec<u8>,)> =
                sqlx::query_as(r#"SELECT oobi_data FROM location_oobis WHERE eid = $1"#)
                    .bind(id.to_string())
                    .fetch_all(&self.pool)
                    .await?;

            Ok(rows
                .into_iter()
                .filter_map(|(oobi_data,)| serde_cbor::from_slice(&oobi_data).ok())
                .collect())
        })
    }

    fn get_last_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, Self::Error> {
        async_std::task::block_on(async {
            let row: Option<(Vec<u8>,)> = sqlx::query_as(
                r#"SELECT oobi_data FROM location_oobis WHERE eid = $1 AND scheme = $2"#,
            )
            .bind(eid.to_string())
            .bind(serde_json::to_string(scheme).unwrap())
            .fetch_optional(&self.pool)
            .await?;

            Ok(row.and_then(|(oobi_data,)| serde_cbor::from_slice(&oobi_data).ok()))
        })
    }

    fn get_end_role(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, Self::Error> {
        async_std::task::block_on(async {
            let rows: Vec<(Vec<u8>,)> = sqlx::query_as(
                r#"SELECT oobi_data FROM end_role_oobis WHERE cid = $1 AND role = $2"#,
            )
            .bind(cid.to_string())
            .bind(serde_json::to_string(&role).unwrap())
            .fetch_all(&self.pool)
            .await?;

            if rows.is_empty() {
                return Ok(None);
            }

            Ok(Some(
                rows.into_iter()
                    .filter_map(|(oobi_data,)| serde_cbor::from_slice(&oobi_data).ok())
                    .collect(),
            ))
        })
    }

    fn save_oobi(&self, signed_reply: &SignedReply) -> Result<(), Self::Error> {
        async_std::task::block_on(async {
            match signed_reply.reply.get_route() {
                ReplyRoute::LocScheme(loc_scheme) => {
                    sqlx::query(
                        r#"INSERT INTO location_oobis (eid, scheme, oobi_data)
                           VALUES ($1, $2, $3)
                           ON CONFLICT (eid, scheme) DO UPDATE SET oobi_data = $3"#,
                    )
                    .bind(loc_scheme.get_eid().to_string())
                    .bind(serde_json::to_string(&loc_scheme.scheme).unwrap())
                    .bind(serde_cbor::to_vec(signed_reply).unwrap())
                    .execute(&self.pool)
                    .await?;
                }
                ReplyRoute::EndRoleAdd(end_role) | ReplyRoute::EndRoleCut(end_role) => {
                    sqlx::query(
                        r#"INSERT INTO end_role_oobis (cid, role, eid, oobi_data)
                           VALUES ($1, $2, $3, $4)"#,
                    )
                    .bind(end_role.cid.to_string())
                    .bind(serde_json::to_string(&end_role.role).unwrap())
                    .bind(end_role.eid.to_string())
                    .bind(serde_cbor::to_vec(signed_reply).unwrap())
                    .execute(&self.pool)
                    .await?;
                }
                _ => {}
            }
            Ok(())
        })
    }
}
