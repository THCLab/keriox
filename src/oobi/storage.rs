use std::path::Path;

use sled::Db;

use crate::database::sled::tables::{SledEventTree, SledEventTreeVec};
use crate::query::reply_event::ReplyRoute;
use crate::{prefix::IdentifierPrefix, query::reply_event::SignedReply};

use super::error::Error;
use super::{EndRole, Scheme};

pub struct OobiStorage {
    identifiers: SledEventTree<IdentifierPrefix>,
    // subdatabase for endpoint providers location schemes
    oobis: SledEventTreeVec<SignedReply>,
    // subdatabase for end role oobis
    cids: SledEventTreeVec<EndRole>,
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
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        let key = self.identifiers.designated_key(id);
        Ok(self.oobis.get(key)?)
    }

    pub fn get_last_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, Error> {
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
        role: &str,
    ) -> Result<Option<Vec<EndRole>>, Error> {
        let key = self.identifiers.designated_key(cid);
        Ok(self.cids.get(key)?.map(|r| {
            r.into_iter()
                .filter(|oobi| oobi.role == role.to_string())
                .collect()
        }))
    }

    pub fn save_oobi(&self, signed_reply: SignedReply) -> Result<(), Error> {
        match signed_reply.reply.get_route() {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(loc_scheme) => {
                let key = self.identifiers.designated_key(&loc_scheme.get_eid());
                // let oobi = oobi_reply.reply.event.content.clone();

                // update last saved reply for given schema with the new one
                match self.oobis.iter_values(key) {
                    Some(values) => {
                        let value = values
                            .filter(|oobi_rpy| {
                                oobi_rpy.reply.get_route()
                                    != ReplyRoute::LocScheme(loc_scheme.clone())
                            })
                            .chain(vec![signed_reply])
                            .collect::<Vec<_>>();
                        self.oobis.put(key, value)
                    }
                    None => self.oobis.push(key, signed_reply),
                }?;
            }
            ReplyRoute::EndRole(end_role) => {
                let key = self.identifiers.designated_key(&end_role.cid);
                // TODO this also will be signed reply
                self.cids.push(key, end_role)?
            }
        };
        Ok(())
    }
}
