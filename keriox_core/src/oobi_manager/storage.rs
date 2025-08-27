use std::sync::Arc;

use redb::{MultimapTableDefinition, TableDefinition};

use super::Role;
use crate::oobi::Scheme;
use crate::{
    database::redb::RedbError,
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
};

/// Location OOBIs store (eid, scheme) -> Signed oobi
const LOCATION: TableDefinition<(&str, &str), &[u8]> = TableDefinition::new("location");

/// End role OOBIs store (cid, role) -> Signed oobi
const END_ROLE: MultimapTableDefinition<(&[u8], &[u8]), &[u8]> =
    MultimapTableDefinition::new("end_role");

pub struct OobiStorage {
    db: Arc<redb::Database>,
}
impl OobiStorage {
    pub fn new(db: Arc<redb::Database>) -> Result<Self, RedbError> {
        // Create tables
        let write_txn = db.begin_write()?;
        {
            write_txn.open_table(LOCATION)?;
            write_txn.open_multimap_table(END_ROLE)?;
        }
        write_txn.commit()?;
        Ok(Self { db })
    }

    pub fn get_oobis_for_eid(&self, id: &IdentifierPrefix) -> Result<Vec<SignedReply>, RedbError> {
        let str_id = id.to_string();
        let start = (str_id.as_str(), "");

        // End of the range: ("apple\u{FFFD}", "")
        // Adding a character greater than any normal Unicode character ensures the end is exclusive
        let mut end_prefix = str_id.to_owned();
        end_prefix.push('\u{FFFD}'); // or use '\u{10FFFF}' for max valid Unicode scalar
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

    pub fn get_last_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, RedbError> {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_table(LOCATION).unwrap();
        let el = table
            .get((
                eid.to_string().as_str(),
                serde_json::to_string(scheme).unwrap().as_str(),
            ))
            .unwrap();

        let out = el.and_then(|entry| {
            // let (_, value) = entry;
            serde_cbor::from_slice::<SignedReply>(entry.value()).ok()
        });
        Ok(out)
    }

    pub fn get_end_role(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, RedbError> {
        let read_txn = self.db.begin_read().unwrap();
        let table = read_txn.open_multimap_table(END_ROLE).unwrap();
        let entry = table
            .get((
                cid.to_string().as_bytes(),
                serde_json::to_vec(&role).unwrap().as_slice(),
            ))
            .unwrap();
        let out: Option<Vec<SignedReply>> = entry
            .map(|entry| {
                let value = entry.unwrap();
                serde_cbor::from_slice::<SignedReply>(value.value()).ok()
            })
            .collect();
        Ok(out)
    }

    pub fn save_oobi(&self, signed_reply: &SignedReply) -> Result<(), RedbError> {
        println!(
            "\n\nSaving oobi for route: {:?}\n",
            signed_reply.reply.get_route()
        );
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
            ReplyRoute::EndRoleAdd(end_role) | ReplyRoute::EndRoleCut(end_role) => {
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
