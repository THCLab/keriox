//! Where registries are kept: their events and the state blocks behind
//! their BLIDs. The blinding salts of an Issuer's registries are not kept
//! here: the Issuer keeps them with its other secrets.
//!
//! Events are kept as their raw bodies and read back through
//! [`RegistryMessage::parse`]. Distinct events at one position are all kept:
//! they are the evidence of duplicity [`verify`](super::verify) reports.

use std::{
    collections::{BTreeMap, HashMap},
    sync::RwLock,
};

use said::SelfAddressingIdentifier;

use super::{RegistryError, RegistryMessage, StateBlock};

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
    fn save_block(&self, block: &StateBlock) -> Result<(), RegistryError>;

    fn block(&self, blid: &SelfAddressingIdentifier) -> Result<Option<StateBlock>, RegistryError>;
}

/// A block as the CESR text of its attachment group.
pub(crate) fn block_to_text(block: &StateBlock) -> Result<String, RegistryError> {
    block.to_group()
}

pub(crate) fn block_from_text(text: &str) -> Result<StateBlock, RegistryError> {
    match StateBlock::parse_group(text)?.as_slice() {
        [block] => Ok(block.clone()),
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
    blocks: RwLock<HashMap<SelfAddressingIdentifier, StateBlock>>,
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
            .insert(key, event.encode());
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

    fn save_block(&self, block: &StateBlock) -> Result<(), RegistryError> {
        self.blocks
            .write()
            .map_err(poisoned)?
            .insert(block.blid()?, block.clone());
        Ok(())
    }

    fn block(&self, blid: &SelfAddressingIdentifier) -> Result<Option<StateBlock>, RegistryError> {
        Ok(self.blocks.read().map_err(poisoned)?.get(blid).cloned())
    }
}

/// The behaviour every backend must share.
#[cfg(test)]
pub(crate) mod conformance {
    use acdc::{registry::BoundState, HashFunctionCode};

    use super::RegistryStore;
    use crate::registry::{Blinding, RegistryMessage, Salt, StateBlock};

    /// Events by position, and at one position by SAID: the order every
    /// backend lists them in.
    fn ordered(mut events: Vec<RegistryMessage>) -> Vec<RegistryMessage> {
        events.sort_by_key(|event| (event.sn(), event.said().unwrap().to_string()));
        events
    }

    pub(crate) fn check(store: &dyn RegistryStore) {
        let time = "2026-01-01T00:00:00.000000+00:00";
        let issuer = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB"
            .parse()
            .unwrap();
        let rip = RegistryMessage::incept(&issuer, &Salt::random().to_qb64(), time).unwrap();
        let registry = rip.said().unwrap();
        let blinding = Blinding::private();
        let update = |state: &str| {
            let block = StateBlock::new(&blinding, 1, None, state).unwrap();
            let bup =
                RegistryMessage::blindable_update(&rip, &block.blid().unwrap(), time).unwrap();
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

        let bound = StateBlock::Bound(
            BoundState::new("", "", "", 0, "", HashFunctionCode::Blake3_256).unwrap(),
        );
        for block in [issued_block, bound] {
            let blid = block.blid().unwrap();
            assert_eq!(store.block(&blid).unwrap(), None);
            store.save_block(&block).unwrap();
            store.save_block(&block).unwrap();
            assert_eq!(store.block(&blid).unwrap(), Some(block));
        }
    }

    #[test]
    fn the_memory_store_keeps_registries() {
        check(&super::MemoryRegistryStore::new());
    }
}
