use std::{collections::HashMap, sync::Mutex};

use keri_core::{error::Error, prefix::IdentifierPrefix};

/// Struct for storing TEL events which were collected from witnesses for
/// identifier. Watcher doesn't check provided TEL events, just save them and
/// forward to recipient when it sends query message.
pub(super) struct TelToForward {
    /// The key is a tuple of Registry identifiers nad Vc idettifier, and the
    /// value is collected TEL events
    tel: Mutex<HashMap<(IdentifierPrefix, IdentifierPrefix), Vec<u8>>>,
}

impl TelToForward {
    pub fn new() -> Self {
        Self {
            tel: Mutex::new(HashMap::new()),
        }
    }

    pub fn save(&self, about_ri: IdentifierPrefix, about_vc_id: IdentifierPrefix, tel: Vec<u8>) {
        let mut saving = self.tel.lock().unwrap();
        saving.insert((about_ri.clone(), about_vc_id.clone()), tel);
    }

    pub fn get(&self, ri: IdentifierPrefix, vc_id: IdentifierPrefix) -> Option<Vec<u8>> {
        let mut saving = self.tel.lock().unwrap();
        saving.remove(&(ri, vc_id))
    }
}

/// Struct for saving mapping between Registry Identifier and identifier of
/// entity that stores corresponding TEL events. (Usually witness identifier).
/// Those are provided to watcher by identifier using oobi.
pub(super) struct RegistryMapping {
    /// Key is registry identifier, and value is witness identifier.
    mapping: Mutex<HashMap<IdentifierPrefix, IdentifierPrefix>>,
}

impl RegistryMapping {
    pub fn new() -> Self {
        Self {
            mapping: Mutex::new(HashMap::new()),
        }
    }
    pub fn save(&self, key: IdentifierPrefix, value: IdentifierPrefix) -> Result<(), Error> {
        let mut data = self.mapping.lock().unwrap();
        data.insert(key, value);
        Ok(())
    }

    pub fn get(&self, key: &IdentifierPrefix) -> Option<IdentifierPrefix> {
        let data = self.mapping.lock().unwrap();
        data.get(key).map(|id| id.clone())
    }
}
