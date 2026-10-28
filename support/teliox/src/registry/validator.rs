//! The Validator's side of a registry: accepting what a Discloser presents
//! once it verifies against the Issuer's KEL, and the state of the
//! registries accepted so far.

use keri_core::{database::EventDatabase, processor::event_storage::EventStorage};
use said::SelfAddressingIdentifier;

use super::{
    registrar::Disclosure, verify, AcdcBinding, RegistryError, RegistryMessage, RegistryState,
    RegistryStore,
};

pub struct Validator<S: RegistryStore> {
    store: S,
}

impl<S: RegistryStore> Validator<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Verifies `disclosure` with the events already accepted of its
    /// registry, and keeps it if it verifies. A disclosure that misses its
    /// anchors is not kept; it can be presented again once the Issuer's KEL
    /// has them.
    pub fn accept<D: EventDatabase>(
        &self,
        kel: &EventStorage<D>,
        disclosure: &Disclosure,
        acdc: Option<&AcdcBinding>,
    ) -> Result<RegistryState, RegistryError> {
        let registry = disclosure.inception.said()?;
        let mut updates = disclosure.updates.clone();
        updates.extend(
            self.store
                .events(&registry)?
                .into_iter()
                .filter(|event| !matches!(event, RegistryMessage::Inception(_))),
        );
        let state = verify(
            kel,
            &disclosure.inception,
            &updates,
            disclosure.block.as_ref(),
            acdc,
        )?;
        for event in std::iter::once(&disclosure.inception).chain(&disclosure.updates) {
            self.store.save_event(event)?;
        }
        if let Some(block) = &disclosure.block {
            self.store.save_block(block)?;
        }
        Ok(state)
    }

    /// The state of an accepted registry, verified again against the
    /// Issuer's KEL as it now stands: a revocation anchored since makes it
    /// stale.
    pub fn state<D: EventDatabase>(
        &self,
        kel: &EventStorage<D>,
        registry: &SelfAddressingIdentifier,
        acdc: Option<&AcdcBinding>,
    ) -> Result<RegistryState, RegistryError> {
        let mut events = self.store.events(registry)?.into_iter();
        let inception = events
            .next()
            .ok_or_else(|| RegistryError::Chain(format!("no registry {registry}")))?;
        let updates: Vec<RegistryMessage> = events.collect();
        let block = match updates.last() {
            Some(RegistryMessage::Blindable(bup)) => self.store.block(&bup.data.blid)?,
            _ => None,
        };
        verify(kel, &inception, &updates, block.as_ref(), acdc)
    }
}
