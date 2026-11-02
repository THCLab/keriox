//! The Issuer's side of a registry: incepting it, updating the state of its
//! ACDCs, and disclosing it. Each new event is returned as a [`Pending`]
//! update with the seal to anchor in the Issuer's KEL; it is kept only once
//! the Issuer has anchored it and [`RegistryIssuer::commit`]s it, so that
//! the registry never runs ahead of its anchors.
//!
//! The [`Blinding`] of a registry is a secret the Issuer keeps itself, with
//! its other secrets: the store never holds it.

use keri_core::{
    event::sections::seal::{DigestSeal, Seal},
    prefix::IdentifierPrefix,
};
use said::SelfAddressingIdentifier;

use super::{
    event::now, Blinding, RegistryError, RegistryMessage, RegistryStore, Salt, StateBlock,
};

/// A registry event the Issuer made and has yet to anchor.
#[derive(Debug, Clone, PartialEq)]
pub struct Pending {
    pub event: RegistryMessage,
    /// The block behind the BLID of a `bup`.
    pub block: Option<StateBlock>,
}

impl Pending {
    /// The seal the Issuer anchors the event with: a digest seal, which
    /// says nothing about the registry or the position of the event, so
    /// that the Issuer's KEL does not reveal its registries' activity.
    pub fn seal(&self) -> Result<Seal, RegistryError> {
        Ok(Seal::Digest(DigestSeal::new(self.event.said()?)))
    }
}

/// What a Discloser presents of a registry: its events and the block of its
/// head.
#[derive(Debug, Clone, PartialEq)]
pub struct Disclosure {
    pub inception: RegistryMessage,
    pub updates: Vec<RegistryMessage>,
    pub block: Option<StateBlock>,
}

pub struct RegistryIssuer<S: RegistryStore> {
    store: S,
}

impl<S: RegistryStore> RegistryIssuer<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// A new registry of `issuer`.
    pub fn incept(&self, issuer: &IdentifierPrefix) -> Result<Pending, RegistryError> {
        Ok(Pending {
            event: RegistryMessage::incept(issuer, &Salt::random().to_qb64(), &now())?,
            block: None,
        })
    }

    /// The next update of `registry`, giving `acdc` the `state`, with its
    /// block blinded as `blinding` says.
    pub fn update(
        &self,
        registry: &SelfAddressingIdentifier,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
        state: &str,
    ) -> Result<Pending, RegistryError> {
        let head = self.head(registry)?;
        let block = StateBlock::new(blinding, head.sn() + 1, Some(acdc), state)?;
        Ok(Pending {
            event: RegistryMessage::blindable_update(&head, &block.blid()?, &now())?,
            block: Some(block),
        })
    }

    /// Issues `acdc` as the first update of the registry `inception`
    /// starts, before either is kept: a credential names its registry, so
    /// the registry is incepted first, the ACDC built naming it, and both
    /// anchored together.
    pub fn issue_after(
        &self,
        inception: &Pending,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<Pending, RegistryError> {
        let block = StateBlock::new(blinding, inception.event.sn() + 1, Some(acdc), "issued")?;
        Ok(Pending {
            event: RegistryMessage::blindable_update(&inception.event, &block.blid()?, &now())?,
            block: Some(block),
        })
    }

    /// Issues `acdc` in `registry`.
    pub fn issue(
        &self,
        registry: &SelfAddressingIdentifier,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<Pending, RegistryError> {
        self.update(registry, blinding, acdc, "issued")
    }

    /// Revokes `acdc` in `registry`.
    pub fn revoke(
        &self,
        registry: &SelfAddressingIdentifier,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<Pending, RegistryError> {
        self.update(registry, blinding, acdc, "revoked")
    }

    /// Keeps an update the Issuer has anchored. It must follow the kept
    /// head, or be the inception of a registry not yet kept.
    pub fn commit(&self, pending: &Pending) -> Result<(), RegistryError> {
        let registry = pending.event.registry()?;
        let said = pending.event.said()?;
        let events = self.store.events(&registry)?;
        match events.last() {
            None if pending.event.issuer().is_some() => {}
            Some(head)
                if pending.event.sn() == head.sn() + 1
                    && pending.event.prior().transpose()? == Some(head.said()?) => {}
            Some(head) if head.said()? == said => return Ok(()),
            _ => {
                return Err(RegistryError::Chain(format!(
                    "update {said} does not follow the head of registry {registry}"
                )))
            }
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
        let block = match updates.last().and_then(RegistryMessage::blid) {
            Some(blid) => self.store.block(&blid?)?,
            None => None,
        };
        Ok(Disclosure {
            inception,
            updates,
            block,
        })
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
    use keri_core::event::sections::seal::Seal;
    use said::SelfAddressingIdentifier;

    use super::{Pending, RegistryIssuer};
    use crate::registry::{
        verify::tests::Issuer, AbandonedIssuer, AcdcBinding, Binding, Blinding,
        MemoryRegistryStore, Policy, RegistryError, RegistryStore, StateBlock, Validator, Verdict,
    };

    fn acdc() -> SelfAddressingIdentifier {
        "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"
            .parse()
            .unwrap()
    }

    /// Anchors the update in the Issuer's KEL, then keeps it.
    fn anchor(
        issuer: &mut Issuer,
        registry: &RegistryIssuer<MemoryRegistryStore>,
        pending: &Pending,
    ) {
        issuer.anchor(vec![pending.seal().unwrap()]);
        registry.commit(pending).unwrap();
    }

    fn valid(verdict: Verdict) -> crate::registry::RegistryState {
        match verdict {
            Verdict::Valid { state, .. } => state,
            other => panic!("{other:?}"),
        }
    }

    /// An Issuer issues and revokes an ACDC in a private registry; a
    /// Validator accepts each disclosure, and the Discloser, holding the
    /// blinding, finds the state behind each BLID.
    #[test]
    fn a_registry_runs_from_issuance_to_revocation() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let blinding = Blinding::private();
        let rip = registrar.incept(&issuer.id).unwrap();
        assert!(matches!(rip.seal().unwrap(), Seal::Digest(_)));
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &blinding, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &issued);

        let presented = AcdcBinding {
            said: acdc(),
            issuer: issuer.id.clone(),
            registry: Some(registry.clone()),
        };
        let validator = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let issued_disclosure = registrar.disclosure(&registry).unwrap();
        let state = valid(
            validator
                .accept(&issuer.storage, &issued_disclosure, Some(&presented))
                .unwrap(),
        );
        assert_eq!(state.state.as_deref(), Some("issued"));
        assert_eq!(state.binding, Some(Binding::Mutual));

        let revoked = registrar.revoke(&registry, &blinding, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &revoked);
        let disclosure = registrar.disclosure(&registry).unwrap();
        assert_eq!(disclosure.updates.len(), 2);
        validator
            .accept(&issuer.storage, &disclosure, Some(&presented))
            .unwrap();
        let state = valid(
            validator
                .state(&issuer.storage, &registry, Some(&presented))
                .unwrap(),
        );
        assert_eq!((state.sn, state.state.as_deref()), (2, Some("revoked")));

        // Having seen the revocation, the Validator is not shown the issued
        // state again by the older disclosure.
        let state = valid(
            validator
                .accept(&issuer.storage, &issued_disclosure, Some(&presented))
                .unwrap(),
        );
        assert_eq!(state.state.as_deref(), Some("revoked"));

        let blid = disclosure.block.unwrap().blid().unwrap();
        let found = StateBlock::unblind(&blid, &blinding, 2, &acdc(), &["issued", "revoked"])
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), "revoked");
    }

    /// A Validator that has not seen the revocation judges a disclosure cut
    /// short of it from what is presented alone: the revoked block without
    /// its update is refused, and the issued state is valid as presented,
    /// since nothing presented proves a later update.
    #[test]
    fn a_disclosure_cut_short_is_judged_as_presented() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let blinding = Blinding::private();
        let rip = registrar.incept(&issuer.id).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &blinding, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &issued);
        let issued_disclosure = registrar.disclosure(&registry).unwrap();
        let revoked = registrar.revoke(&registry, &blinding, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &revoked);

        let presented = AcdcBinding {
            said: acdc(),
            issuer: issuer.id.clone(),
            registry: Some(registry.clone()),
        };
        let mut cut = registrar.disclosure(&registry).unwrap();
        cut.updates.pop();
        let validator = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let verdict = validator
            .accept(&issuer.storage, &cut, Some(&presented))
            .unwrap();
        assert!(
            matches!(verdict, Verdict::Rejected(RegistryError::Blind(_))),
            "{verdict:?}"
        );
        assert!(validator.store().events(&registry).unwrap().is_empty());

        let state = valid(
            validator
                .accept(&issuer.storage, &issued_disclosure, Some(&presented))
                .unwrap(),
        );
        assert_eq!(state.state.as_deref(), Some("issued"));
    }

    /// A public registry's blocks carry no blind: anyone can tell the state.
    #[test]
    fn a_public_registry_carries_no_blind() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar
            .issue(&registry, &Blinding::Public, &acdc())
            .unwrap();
        let block = issued.block.unwrap();
        let guessed = StateBlock::new(&Blinding::Public, 1, Some(&acdc()), "issued").unwrap();
        assert_eq!(block.blid().unwrap(), guessed.blid().unwrap());
    }

    /// An update made before another was kept no longer follows the head.
    #[test]
    fn an_update_that_lost_the_race_is_refused() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let blinding = Blinding::private();
        let rip = registrar.incept(&issuer.id).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar.issue(&registry, &blinding, &acdc()).unwrap();
        let revoked = registrar.revoke(&registry, &blinding, &acdc()).unwrap();
        anchor(&mut issuer, &registrar, &issued);
        registrar.commit(&issued).unwrap();
        assert!(matches!(
            registrar.commit(&revoked),
            Err(RegistryError::Chain(_))
        ));
    }

    /// A disclosure whose anchor has not reached the Validator's copy of the
    /// KEL is indeterminate, and not kept.
    #[test]
    fn an_unanchored_disclosure_is_indeterminate() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar
            .issue(&registry, &Blinding::private(), &acdc())
            .unwrap();
        registrar.commit(&issued).unwrap();

        let validator = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let disclosure = registrar.disclosure(&registry).unwrap();
        let verdict = validator
            .accept(&issuer.storage, &disclosure, None)
            .unwrap();
        assert!(
            matches!(
                verdict,
                Verdict::Indeterminate(RegistryError::MissingAnchor(_))
            ),
            "{verdict:?}"
        );
        assert!(validator.store().events(&registry).unwrap().is_empty());
    }

    /// Credentials of an Issuer that later abandoned its identifier keep
    /// their state by default; a Validator may reject them instead.
    #[test]
    fn an_abandoned_issuer_is_judged_by_policy() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let rip = registrar.incept(&issuer.id).unwrap();
        anchor(&mut issuer, &registrar, &rip);
        let registry = rip.event.said().unwrap();
        let issued = registrar
            .issue(&registry, &Blinding::Public, &acdc())
            .unwrap();
        anchor(&mut issuer, &registrar, &issued);
        issuer.abandon();
        assert!(issuer.storage.get_state(&issuer.id).unwrap().is_abandoned());

        let disclosure = registrar.disclosure(&registry).unwrap();
        let accepting = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let state = valid(
            accepting
                .accept(&issuer.storage, &disclosure, None)
                .unwrap(),
        );
        assert_eq!(state.state.as_deref(), Some("issued"));

        let rejecting = Validator::new(
            MemoryRegistryStore::new(),
            Policy {
                abandoned_issuer: AbandonedIssuer::Reject,
            },
        );
        let verdict = rejecting
            .accept(&issuer.storage, &disclosure, None)
            .unwrap();
        assert_eq!(
            verdict,
            Verdict::Rejected(RegistryError::AbandonedIssuer(issuer.id.clone()))
        );
    }
}
