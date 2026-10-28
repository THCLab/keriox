//! The Issuer's side of a registry: incepting it, updating the state of its
//! ACDCs, and disclosing it. Each new event is returned as a [`Pending`]
//! update with the seal to anchor in the Issuer's KEL; it is kept only once
//! the Issuer has anchored it and [`Registrar::commit`]s it, so that the
//! registry never runs ahead of its anchors.

use keri_core::{
    event::sections::seal::{EventSeal, Seal},
    prefix::IdentifierPrefix,
};
use said::SelfAddressingIdentifier;

use super::{
    event::{build, now, BlindableUpdate, Inception},
    BlindedState, RegistryError, RegistryMessage, RegistryStore, Salt,
};

/// Whether a registry's updates hide their state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blinding {
    /// Every block is blinded with a blind derived from the registry's salt,
    /// which the Issuer shares only with Disclosers.
    Private,
    /// Blocks carry no blind: anyone can tell the state behind a BLID from
    /// the ACDC SAID and the possible states.
    Public,
}

/// A registry event the Issuer made and has yet to anchor.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub event: RegistryMessage,
    /// The block behind the BLID of a `bup`.
    pub block: Option<BlindedState>,
    /// The salt of a newly incepted private registry.
    salt: Option<Salt>,
}

impl Pending {
    /// The seal the Issuer anchors the event with: an event seal naming the
    /// registry and the position, as keripy writes it, so that Validators
    /// can tell when a later update exists.
    pub fn seal(&self) -> Result<Seal, RegistryError> {
        Ok(Seal::Event(EventSeal::new(
            IdentifierPrefix::SelfAddressing(self.event.registry()?.into()),
            self.event.sn(),
            self.event.said()?,
        )))
    }
}

/// What a Discloser presents of a registry: its events and the block of its
/// head.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure {
    pub inception: RegistryMessage,
    pub updates: Vec<RegistryMessage>,
    pub block: Option<BlindedState>,
}

pub struct Registrar<S: RegistryStore> {
    store: S,
}

impl<S: RegistryStore> Registrar<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// A new registry of `issuer`.
    pub fn incept(
        &self,
        issuer: &IdentifierPrefix,
        blinding: Blinding,
    ) -> Result<Pending, RegistryError> {
        let event = RegistryMessage::Inception(build(Inception {
            nonce: Salt::random().to_qb64(),
            issuer: issuer.clone(),
            sn: 0,
            timestamp: now(),
        }));
        Ok(Pending {
            event,
            block: None,
            salt: (blinding == Blinding::Private).then(Salt::random),
        })
    }

    /// The next update of `registry`, giving `acdc` the `state`.
    pub fn update(
        &self,
        registry: &SelfAddressingIdentifier,
        acdc: &SelfAddressingIdentifier,
        state: &str,
    ) -> Result<Pending, RegistryError> {
        let head = self.head(registry)?;
        let sn = head.sn() + 1;
        let block = match self.store.salt(registry)? {
            Some(salt) => BlindedState::blind(&salt, sn, Some(acdc.clone()), state, None)?,
            None => BlindedState::new(None, Some(acdc.clone()), state, None)?,
        };
        let event = RegistryMessage::Blindable(build(BlindableUpdate {
            registry: registry.clone(),
            sn,
            prior: head.said()?,
            timestamp: now(),
            blid: block.blid.clone(),
        }));
        Ok(Pending {
            event,
            block: Some(block),
            salt: None,
        })
    }

    /// Issues `acdc` in `registry`.
    pub fn issue(
        &self,
        registry: &SelfAddressingIdentifier,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<Pending, RegistryError> {
        self.update(registry, acdc, "issued")
    }

    /// Revokes `acdc` in `registry`.
    pub fn revoke(
        &self,
        registry: &SelfAddressingIdentifier,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<Pending, RegistryError> {
        self.update(registry, acdc, "revoked")
    }

    /// Keeps an update the Issuer has anchored. It must follow the kept
    /// head, or be the inception of a registry not yet kept.
    pub fn commit(&self, pending: &Pending) -> Result<(), RegistryError> {
        let registry = pending.event.registry()?;
        let events = self.store.events(&registry)?;
        match (events.last(), &pending.event) {
            (None, RegistryMessage::Inception(_)) => {}
            (Some(head), update)
                if update.sn() == head.sn() + 1 && update.prior() == Some(&head.said()?) => {}
            (Some(head), update) if update.said()? == head.said()? => return Ok(()),
            _ => {
                return Err(RegistryError::Chain(format!(
                    "update {} does not follow the head of registry {registry}",
                    pending.event.said()?
                )))
            }
        }
        if let Some(salt) = &pending.salt {
            self.store.save_salt(&registry, salt)?;
        }
        if let Some(block) = &pending.block {
            self.store.save_block(block)?;
        }
        self.store.save_event(&pending.event)
    }

    /// The registry as a Discloser presents it.
    pub fn disclosure(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Disclosure, RegistryError> {
        let mut events = self.store.events(registry)?.into_iter();
        let inception = events
            .next()
            .ok_or_else(|| RegistryError::Chain(format!("no registry {registry}")))?;
        let updates: Vec<RegistryMessage> = events.collect();
        let block = match updates.last() {
            Some(RegistryMessage::Blindable(bup)) => self.store.block(&bup.data.blid)?,
            _ => None,
        };
        Ok(Disclosure {
            inception,
            updates,
            block,
        })
    }

    /// The salt a Discloser needs to unblind the registry's updates.
    pub fn salt(&self, registry: &SelfAddressingIdentifier) -> Result<Option<Salt>, RegistryError> {
        self.store.salt(registry)
    }

    fn head(&self, registry: &SelfAddressingIdentifier) -> Result<RegistryMessage, RegistryError> {
        self.store
            .events(registry)?
            .pop()
            .ok_or_else(|| RegistryError::Chain(format!("no registry {registry}")))
    }
}

#[cfg(test)]
mod tests {
    use said::SelfAddressingIdentifier;

    use super::{Blinding, Pending, Registrar};
    use crate::registry::{
        verify::tests::Issuer, AcdcBinding, Binding, BlindedState, MemoryRegistryStore,
        RegistryError, RegistryStore, Validator,
    };

    fn acdc() -> SelfAddressingIdentifier {
        "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"
            .parse()
            .unwrap()
    }

    /// Anchors the update in the Issuer's KEL, then keeps it.
    fn anchor(issuer: &mut Issuer, registrar: &Registrar<MemoryRegistryStore>, pending: &Pending) {
        issuer.anchor(vec![pending.seal().unwrap()]);
        registrar.commit(pending).unwrap();
    }

    /// An Issuer issues and revokes an ACDC in a private registry; a
    /// Validator accepts the disclosed issuance, finds it stale once the
    /// revocation is anchored, and accepts the revocation when disclosed.
    #[test]
    fn a_registry_runs_from_issuance_to_revocation() {
        let mut issuer = Issuer::new();
        let registrar = Registrar::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id, Blinding::Private).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        anchor(
            &mut issuer,
            &registrar,
            &registrar.issue(&registry, &acdc()).unwrap(),
        );

        let presented = AcdcBinding {
            said: acdc(),
            issuer: issuer.id.clone(),
            registry: Some(registry.clone()),
        };
        let validator = Validator::new(MemoryRegistryStore::new());
        let disclosure = registrar.disclosure(&registry).unwrap();
        let state = validator
            .accept(&issuer.storage, &disclosure, Some(&presented))
            .unwrap();
        assert_eq!(state.state.as_deref(), Some("issued"));
        assert_eq!(state.binding, Some(Binding::Mutual));

        anchor(
            &mut issuer,
            &registrar,
            &registrar.revoke(&registry, &acdc()).unwrap(),
        );
        let stale = validator.state(&issuer.storage, &registry, Some(&presented));
        assert!(matches!(stale, Err(RegistryError::Stale(_))), "{stale:?}");

        let disclosure = registrar.disclosure(&registry).unwrap();
        assert_eq!(disclosure.updates.len(), 2);
        validator
            .accept(&issuer.storage, &disclosure, Some(&presented))
            .unwrap();
        let state = validator
            .state(&issuer.storage, &registry, Some(&presented))
            .unwrap();
        assert_eq!((state.sn, state.state.as_deref()), (2, Some("revoked")));

        // The Discloser, holding the salt, finds the state behind each BLID.
        let salt = registrar.salt(&registry).unwrap().unwrap();
        let blid = &disclosure.block.as_ref().unwrap().blid;
        let found = BlindedState::unblind(blid, &salt, 2, &acdc(), &["issued", "revoked"])
            .unwrap()
            .unwrap();
        assert_eq!(found.state, "revoked");
    }

    /// A public registry keeps no salt and blinds nothing.
    #[test]
    fn a_public_registry_carries_no_blind() {
        let mut issuer = Issuer::new();
        let registrar = Registrar::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id, Blinding::Public).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &acdc()).unwrap();
        assert_eq!(issued.block.as_ref().unwrap().uuid, None);
        assert_eq!(registrar.salt(&registry).unwrap(), None);
    }

    /// An update made before another was kept no longer follows the head.
    #[test]
    fn an_update_that_lost_the_race_is_refused() {
        let mut issuer = Issuer::new();
        let registrar = Registrar::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id, Blinding::Private).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &acdc()).unwrap();
        let revoked = registrar.revoke(&registry, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &issued);
        registrar.commit(&issued).unwrap();
        assert!(matches!(
            registrar.commit(&revoked),
            Err(RegistryError::Chain(_))
        ));
    }

    /// A disclosure whose anchor has not reached the Validator's copy of the
    /// KEL is not kept.
    #[test]
    fn an_unanchored_disclosure_is_not_kept() {
        let mut issuer = Issuer::new();
        let registrar = Registrar::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id, Blinding::Private).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &acdc()).unwrap();
        registrar.commit(&issued).unwrap();

        let validator = Validator::new(MemoryRegistryStore::new());
        let disclosure = registrar.disclosure(&registry).unwrap();
        let result = validator.accept(&issuer.storage, &disclosure, None);
        assert!(matches!(result, Err(RegistryError::MissingAnchor(_))));
        assert!(validator.store().events(&registry).unwrap().is_empty());
    }
}
