use std::path::Path;

use sled::Db;

use crate::database::sled::tables::{SledEventTree, SledEventTreeVec};
use crate::{prefix::IdentifierPrefix, query::reply_event::SignedReply};

use super::{error::Error, Oobi};

pub struct OobiStorage {
    identifiers: SledEventTree<IdentifierPrefix>,
    oobis: SledEventTreeVec<SignedReply<Oobi>>,
}

impl OobiStorage {
    pub fn new(db_path: &Path) -> Result<Self, Error> {
        let db: Db = sled::open(db_path)?;
        Ok(OobiStorage {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            oobis: SledEventTreeVec::new(db.open_tree(b"oobis")?),
        })
    }

    pub fn get_full_reply(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply<Oobi>>>, Error> {
        let key = self.identifiers.designated_key(id);
        Ok(self.oobis.get(key)?)
    }

    pub fn get_urls(&self, id: &IdentifierPrefix) -> Result<Option<Vec<url::Url>>, Error> {
        let oobi_rpy = self.get_full_reply(id);
        oobi_rpy.map(|some_reply| {
            some_reply.map(|oobi_rpy_list| {
                oobi_rpy_list
                    .into_iter()
                    .map(|oobi_rpy| oobi_rpy.reply.event.content.data.data.url)
                    .collect()
            })
        })
    }

    pub fn save(&self, sr: SignedReply<Oobi>) -> Result<(), Error> {
        let key = self
            .identifiers
            .designated_key(&sr.reply.event.content.data.data.eid);
        Ok(self.oobis.push(key, sr)?)
    }
}
