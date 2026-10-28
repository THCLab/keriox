//! Where registries are kept: their events, the blinded state blocks behind
//! their BLIDs, and, for the registries an Issuer runs, the salt their
//! blinds derive from.
//!
//! Events are kept as their raw bodies and read back through
//! [`RegistryMessage::parse`]. Distinct events at one position are all kept:
//! they are the evidence of duplicity [`verify`](super::verify) reports.

use std::{
    collections::{BTreeMap, HashMap},
    sync::RwLock,
};

use cesrox::group::parse_group;
use said::SelfAddressingIdentifier;

use super::{BlindedState, RegistryError, RegistryMessage, Salt};

#[cfg(feature = "storage-postgres")]
pub mod postgres;
#[cfg(feature = "storage-redb")]
pub mod redb;

pub trait RegistryStore: Send + Sync {
    /// Keeps `event`; keeping it again changes nothing.
    fn save_event(&self, event: &RegistryMessage) -> Result<(), RegistryError>;

    /// The events of `registry`, ordered by position: its inception first.
    fn events(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Vec<RegistryMessage>, RegistryError>;

    /// Keeps `block` under its BLID.
    fn save_block(&self, block: &BlindedState) -> Result<(), RegistryError>;

    fn block(&self, blid: &SelfAddressingIdentifier)
        -> Result<Option<BlindedState>, RegistryError>;

    /// Keeps the salt of a registry the Issuer runs. The salt is a secret
    /// shared only with Disclosers: whoever reads it can unblind every
    /// update of the registry.
    fn save_salt(
        &self,
        registry: &SelfAddressingIdentifier,
        salt: &Salt,
    ) -> Result<(), RegistryError>;

    fn salt(&self, registry: &SelfAddressingIdentifier) -> Result<Option<Salt>, RegistryError>;
}

/// A block as the CESR text of its attachment group.
pub(crate) fn block_to_text(block: &BlindedState) -> Result<String, RegistryError> {
    Ok(block.to_group()?.to_cesr_str())
}

pub(crate) fn block_from_text(text: &str) -> Result<BlindedState, RegistryError> {
    let (group, rest) = parse_group(text.as_bytes())
        .map_err(|e| RegistryError::Storage(format!("stored block: {e}")))?;
    match (rest, BlindedState::from_group(&group)?.as_slice()) {
        ([], [block]) => Ok(block.clone()),
        _ => Err(RegistryError::Storage(
            "stored block is not one block".into(),
        )),
    }
}

/// Raw event bodies by position and SAID.
type RawEvents = BTreeMap<(u64, String), Vec<u8>>;

/// A store in memory, for tests and short-lived validators.
#[derive(Default)]
pub struct MemoryRegistryStore {
    events: RwLock<HashMap<SelfAddressingIdentifier, RawEvents>>,
    blocks: RwLock<HashMap<SelfAddressingIdentifier, BlindedState>>,
    salts: RwLock<HashMap<SelfAddressingIdentifier, Salt>>,
}

impl MemoryRegistryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

fn poisoned<T>(_: T) -> RegistryError {
    RegistryError::Storage("lock poisoned".into())
}

impl RegistryStore for MemoryRegistryStore {
    fn save_event(&self, event: &RegistryMessage) -> Result<(), RegistryError> {
        let key = (event.sn(), event.said()?.to_string());
        self.events
            .write()
            .map_err(poisoned)?
            .entry(event.registry()?)
            .or_default()
            .insert(key, event.encode()?);
        Ok(())
    }

    fn events(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Vec<RegistryMessage>, RegistryError> {
        let events = self.events.read().map_err(poisoned)?;
        events
            .get(registry)
            .into_iter()
            .flat_map(|events| events.values())
            .map(|raw| RegistryMessage::parse(raw))
            .collect()
    }

    fn save_block(&self, block: &BlindedState) -> Result<(), RegistryError> {
        self.blocks
            .write()
            .map_err(poisoned)?
            .insert(block.blid.clone(), block.clone());
        Ok(())
    }

    fn block(
        &self,
        blid: &SelfAddressingIdentifier,
    ) -> Result<Option<BlindedState>, RegistryError> {
        Ok(self.blocks.read().map_err(poisoned)?.get(blid).cloned())
    }

    fn save_salt(
        &self,
        registry: &SelfAddressingIdentifier,
        salt: &Salt,
    ) -> Result<(), RegistryError> {
        self.salts
            .write()
            .map_err(poisoned)?
            .insert(registry.clone(), salt.clone());
        Ok(())
    }

    fn salt(&self, registry: &SelfAddressingIdentifier) -> Result<Option<Salt>, RegistryError> {
        Ok(self.salts.read().map_err(poisoned)?.get(registry).cloned())
    }
}

/// The behaviour every backend must share.
#[cfg(test)]
pub(crate) mod conformance {
    use super::RegistryStore;
    use crate::registry::{
        event::{build, BlindableUpdate, Inception},
        BlindedState, RegistryMessage, Salt,
    };

    /// Events by position, and at one position by SAID: the order every
    /// backend lists them in.
    fn ordered(mut events: Vec<RegistryMessage>) -> Vec<RegistryMessage> {
        events.sort_by_key(|event| (event.sn(), event.said().unwrap().to_string()));
        events
    }

    pub(crate) fn check(store: &dyn RegistryStore) {
        let time = chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00+00:00").unwrap();
        let rip = RegistryMessage::Inception(build(Inception {
            nonce: Salt::random().to_qb64(),
            issuer: "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB"
                .parse()
                .unwrap(),
            sn: 0,
            timestamp: time,
        }));
        let registry = rip.said().unwrap();
        let salt = Salt::random();
        let update = |state: &str| {
            let block = BlindedState::blind(&salt, 1, None, state, Some((0, None))).unwrap();
            let bup = RegistryMessage::Blindable(build(BlindableUpdate {
                registry: registry.clone(),
                sn: 1,
                prior: registry.clone(),
                timestamp: time,
                blid: block.blid.clone(),
            }));
            (bup, block)
        };
        let (issued, issued_block) = update("issued");
        let (fork, _) = update("revoked");

        assert!(store.events(&registry).unwrap().is_empty());
        for event in [&fork, &issued, &rip, &issued] {
            store.save_event(event).unwrap();
        }
        let expected = ordered(vec![rip.clone(), issued.clone(), fork.clone()]);
        assert_eq!(store.events(&registry).unwrap(), expected);
        assert_eq!(expected[0], rip);

        assert_eq!(store.block(&issued_block.blid).unwrap(), None);
        store.save_block(&issued_block).unwrap();
        store.save_block(&issued_block).unwrap();
        assert_eq!(store.block(&issued_block.blid).unwrap(), Some(issued_block));

        assert_eq!(store.salt(&registry).unwrap(), None);
        store.save_salt(&registry, &salt).unwrap();
        assert_eq!(store.salt(&registry).unwrap(), Some(salt));
    }

    #[test]
    fn the_memory_store_keeps_registries() {
        check(&super::MemoryRegistryStore::new());
    }
}
