use crate::{
    prefix::IdentifierPrefix,
    query::reply_event::SignedReply,
};

use super::Role;
use crate::oobi::Scheme;

pub trait OobiStorageBackend: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn get_oobis_for_eid(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, Self::Error>;

    fn get_last_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, Self::Error>;

    fn get_end_role(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, Self::Error>;

    fn save_oobi(&self, signed_reply: &SignedReply) -> Result<(), Self::Error>;
}

#[cfg(feature = "storage-redb")]
mod redb_backend {
    use std::sync::Arc;

    use redb::{MultimapTableDefinition, TableDefinition};

    use crate::{
        database::redb::RedbError,
        oobi::Scheme,
        prefix::IdentifierPrefix,
        query::reply_event::{ReplyRoute, SignedReply},
    };

    use super::{super::Role, OobiStorageBackend};

    /// Location OOBIs store (eid, scheme) -> Signed oobi
    const LOCATION: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("location");

    /// End role OOBIs store (cid, role) -> Signed oobi
    const END_ROLE: MultimapTableDefinition<(&[u8], &[u8]), &[u8]> =
        MultimapTableDefinition::new("end_role");

    pub struct RedbOobiStorage {
        pub(super) db: Arc<redb::Database>,
    }

    impl RedbOobiStorage {
        pub fn new(db: Arc<redb::Database>) -> Result<Self, RedbError> {
            let write_txn = db.begin_write()?;
            {
                write_txn.open_table(LOCATION)?;
                write_txn.open_multimap_table(END_ROLE)?;
            }
            write_txn.commit()?;
            Ok(Self { db })
        }
    }

    impl OobiStorageBackend for RedbOobiStorage {
        type Error = RedbError;

        fn get_oobis_for_eid(
            &self,
            id: &IdentifierPrefix,
        ) -> Result<Vec<SignedReply>, Self::Error> {
            let str_id = id.to_string();
            let start = (str_id.as_str(), "");

            let mut end_prefix = str_id.to_owned();
            end_prefix.push('\u{FFFD}');
            let end = (end_prefix.as_str(), "");

            let signed_oobis = {
                let read_txn = self.db.begin_read().unwrap();
                let table = read_txn.open_table(LOCATION).unwrap();
                table.range(start..end)
            }
            .unwrap();

            let out = signed_oobis
                .filter_map(|entry| {
                    let (_, value) = entry.unwrap();
                    serde_cbor::from_slice::<SignedReply>(value.value()).ok()
                })
                .collect();
            Ok(out)
        }

        fn get_last_loc_scheme(
            &self,
            eid: &IdentifierPrefix,
            scheme: &Scheme,
        ) -> Result<Option<SignedReply>, Self::Error> {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_table(LOCATION).unwrap();
            let el = table
                .get((
                    eid.to_string().as_str(),
                    serde_json::to_string(scheme).unwrap().as_str(),
                ))
                .unwrap();

            let out =
                el.and_then(|entry| serde_cbor::from_slice::<SignedReply>(entry.value()).ok());
            Ok(out)
        }

        fn get_end_role(
            &self,
            cid: &IdentifierPrefix,
            role: Role,
        ) -> Result<Option<Vec<SignedReply>>, Self::Error> {
            let read_txn = self.db.begin_read().unwrap();
            let table = read_txn.open_multimap_table(END_ROLE).unwrap();
            let entries: Vec<SignedReply> = table
                .get((
                    cid.to_string().as_bytes(),
                    serde_json::to_vec(&role).unwrap().as_slice(),
                ))
                .unwrap()
                .filter_map(|e| {
                    let value = e.unwrap();
                    serde_cbor::from_slice::<SignedReply>(value.value()).ok()
                })
                .collect();
            Ok(if entries.is_empty() {
                None
            } else {
                Some(entries)
            })
        }

        fn save_oobi(&self, signed_reply: &SignedReply) -> Result<(), Self::Error> {
            match signed_reply.reply.get_route() {
                ReplyRoute::Ksn(_, _) => todo!(),
                ReplyRoute::LocScheme(loc_scheme) => {
                    let (cid, scheme) = (
                        loc_scheme.get_eid().to_string(),
                        serde_json::to_string(&loc_scheme.scheme).unwrap(),
                    );

                    let write_txn = self.db.begin_write().unwrap();
                    {
                        let mut table = (&write_txn).open_table(LOCATION).unwrap();
                        table
                            .insert(
                                (cid.as_str(), scheme.as_str()),
                                serde_cbor::to_vec(signed_reply).unwrap().as_slice(),
                            )
                            .unwrap();
                    }
                    write_txn.commit().unwrap();
                }
                ReplyRoute::EndRoleAdd(end_role) => {
                    let (eid, role) = (
                        end_role.cid.to_string(),
                        serde_json::to_vec(&end_role.role).unwrap(),
                    );

                    let write_txn = self.db.begin_write().unwrap();
                    {
                        let mut table = (&write_txn).open_multimap_table(END_ROLE).unwrap();
                        table
                            .insert(
                                (eid.as_bytes(), role.as_slice()),
                                serde_cbor::to_vec(signed_reply).unwrap().as_slice(),
                            )
                            .unwrap();
                    }
                    write_txn.commit().unwrap();
                }
                ReplyRoute::EndRoleCut(end_role) => {
                    // TODO: EndRoleCut should remove the role from storage, not insert.
                    // Currently mirrors redb's behaviour (inserting the Cut event) pending
                    // a proper removal implementation.
                    let (eid, role) = (
                        end_role.cid.to_string(),
                        serde_json::to_vec(&end_role.role).unwrap(),
                    );

                    let write_txn = self.db.begin_write().unwrap();
                    {
                        let mut table = (&write_txn).open_multimap_table(END_ROLE).unwrap();
                        table
                            .insert(
                                (eid.as_bytes(), role.as_slice()),
                                serde_cbor::to_vec(signed_reply).unwrap().as_slice(),
                            )
                            .unwrap();
                    }
                    write_txn.commit().unwrap();
                }
            }
            Ok(())
        }
    }
}

#[cfg(feature = "storage-redb")]
pub use redb_backend::RedbOobiStorage;
