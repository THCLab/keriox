use std::path::Path;

use sled::Db;

use super::{Role, Scheme};
use crate::{
    database::sled::{
        tables::{SledEventTree, SledEventTreeVec},
        DbError,
    },
    error::Error,
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
};

pub struct OobiStorage {
    identifiers: SledEventTree<IdentifierPrefix>,
    // subdatabase for endpoint providers location schemes
    oobis: SledEventTreeVec<SignedReply>,
    // subdatabase for end role oobis
    cids: SledEventTreeVec<SignedReply>,
}

impl OobiStorage {
    pub fn new(db_path: &Path) -> Result<Self, Error> {
        let db: Db = sled::open(db_path)?;
        Ok(OobiStorage {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            oobis: SledEventTreeVec::new(db.open_tree(b"oobis")?),
            cids: SledEventTreeVec::new(db.open_tree(b"cids")?),
        })
    }

    pub fn get_oobis_for_eid(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, DbError> {
        let key = self.identifiers.designated_key(id)?;
        Ok(self.oobis.get(key)?)
    }

    pub fn get_last_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, DbError> {
        Ok(match self.get_oobis_for_eid(eid)? {
            Some(oobis) => oobis.into_iter().find(|rpy| {
                if let ReplyRoute::LocScheme(lc) = rpy.reply.get_route() {
                    &lc.scheme == scheme
                } else {
                    false
                }
            }),
            None => None,
        })
    }

    pub fn get_end_role(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, DbError> {
        let key = self.identifiers.designated_key(cid)?;
        Ok(self.cids.get(key)?.map(|r| {
            r.into_iter()
                .filter(|oobi| {
                    if let ReplyRoute::EndRoleAdd(er) = oobi.reply.get_route() {
                        er.role == role
                    } else {
                        false
                    }
                })
                .collect()
        }))
    }

    pub fn save_oobi(&self, signed_reply: &SignedReply) -> Result<(), DbError> {
        match signed_reply.reply.get_route() {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(loc_scheme) => {
                let key = self.identifiers.designated_key(&loc_scheme.get_eid())?;

                // update last saved reply for given schema with the new one
                match self.oobis.iter_values(key) {
                    Some(values) => {
                        let value = values
                            .filter(|oobi_rpy| {
                                oobi_rpy.reply.get_route()
                                    != ReplyRoute::LocScheme(loc_scheme.clone())
                            })
                            .chain(vec![signed_reply.clone()])
                            .collect::<Vec<_>>();
                        self.oobis.put(key, value)?;
                    }
                    None => self.oobis.push(key, signed_reply.clone())?,
                }
            }
            ReplyRoute::EndRoleAdd(end_role) | ReplyRoute::EndRoleCut(end_role) => {
                let key = self.identifiers.designated_key(&end_role.cid)?;
                self.cids.push(key, signed_reply.clone())?;
            }
        }
        Ok(())
    }
}
