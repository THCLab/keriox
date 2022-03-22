use std::{collections::HashMap, sync::Mutex};

use crate::{prefix::IdentifierPrefix, query::reply_event::SignedReply};

use super::{error::Error, Oobi};

#[derive(Default)]
pub struct OobiStorage {
    store: Mutex<HashMap<IdentifierPrefix, SignedReply<Oobi>>>,
}

impl OobiStorage {
    pub fn new() -> Self {
        OobiStorage {
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn get(&self, id: &IdentifierPrefix) -> Result<Option<SignedReply<Oobi>>, Error> {
        let oobi = self.store.lock().unwrap().get(id).map(|o| o.to_owned());
        Ok(oobi)
    }

    pub fn save(&self, sr: SignedReply<Oobi>) {
        let pref = sr.reply.event.content.data.data.eid.clone();
        self.store.lock().unwrap().insert(pref, sr);
    }
}
