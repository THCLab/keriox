//! The Validator's side of a registry: judging what a Discloser presents
//! against the Issuer's KEL under the Validator's policy, keeping what it
//! accepts, and judging the kept registries again later.

use keri_core::{
    database::EventDatabase, prefix::IdentifierPrefix, processor::event_storage::EventStorage,
};
use said::SelfAddressingIdentifier;

use super::{
    issuer::Disclosure, verify, AcdcBinding, RegistryError, RegistryIlk, RegistryMessage,
    RegistryState, RegistryStore,
};

/// What a Validator does with credentials of an Issuer that has since
/// abandoned its identifier (rotated to no next keys). It is case specific,
/// so it is the Validator's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AbandonedIssuer {
    /// Credentials anchored before the abandonment keep their state. An
    /// Issuer that wants them revoked revokes them before abandoning.
    #[default]
    Accept,
    /// Credentials of an abandoned Issuer are rejected.
    Reject,
}

/// How a Validator judges registry evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub abandoned_issuer: AbandonedIssuer,
}

/// What a valid state rests on.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Evidence {
    /// The events and block a Discloser presented, anchored in the Issuer's
    /// KEL. The state is valid as presented: nothing proves that no later
    /// update exists.
    Disclosure,
}

/// The Validator's judgement of a registry.
#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Valid {
        state: RegistryState,
        evidence: Evidence,
    },
    /// The evidence is not complete yet, such as an anchor not yet in the
    /// Validator's copy of the Issuer's KEL; it may be judged again later.
    Indeterminate(RegistryError),
    Rejected(RegistryError),
}

pub struct Validator<S: RegistryStore> {
    store: S,
    policy: Policy,
}

impl<S: RegistryStore> Validator<S> {
    pub fn new(store: S, policy: Policy) -> Self {
        Self { store, policy }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// Judges `disclosure` with the events already accepted of its
    /// registry, and keeps it if it is valid. Fails only when the store
    /// does.
    pub fn accept<D: EventDatabase>(
        &self,
        kel: &EventStorage<D>,
        disclosure: &Disclosure,
        acdc: Option<&AcdcBinding>,
    ) -> Result<Verdict, RegistryError> {
        let registry = disclosure.inception.said()?;
        let mut updates = disclosure.updates.clone();
        updates.extend(
            self.store
                .events(&registry)?
                .into_iter()
                .filter(|event| event.ilk() != RegistryIlk::Rip),
        );
        let verified = verify(
            kel,
            &disclosure.inception,
            &updates,
            disclosure.block.as_ref(),
            acdc,
        );
        let verdict = self.judge(kel, verified)?;
        if matches!(verdict, Verdict::Valid { .. }) {
            for event in std::iter::once(&disclosure.inception).chain(&disclosure.updates) {
                self.store.save_event(event)?;
            }
            if let Some(block) = &disclosure.block {
                self.store.save_block(block)?;
            }
        }
        Ok(verdict)
    }

    /// Judges an accepted registry again against the Issuer's KEL as it now
    /// stands.
    pub fn state<D: EventDatabase>(
        &self,
        kel: &EventStorage<D>,
        registry: &SelfAddressingIdentifier,
        acdc: Option<&AcdcBinding>,
    ) -> Result<Verdict, RegistryError> {
        let mut events = self.store.events(registry)?.into_iter();
        let Some(inception) = events.next() else {
            return Ok(Verdict::Indeterminate(RegistryError::Chain(format!(
                "no registry {registry}"
            ))));
        };
        let updates: Vec<RegistryMessage> = events.collect();
        let block = match updates.last().and_then(RegistryMessage::blid) {
            Some(blid) => self.store.block(&blid?)?,
            None => None,
        };
        let verified = verify(kel, &inception, &updates, block.as_ref(), acdc);
        self.judge(kel, verified)
    }

    fn judge<D: EventDatabase>(
        &self,
        kel: &EventStorage<D>,
        verified: Result<RegistryState, RegistryError>,
    ) -> Result<Verdict, RegistryError> {
        let state = match verified {
            Ok(state) => state,
            Err(e @ RegistryError::Storage(_)) => return Err(e),
            Err(e @ RegistryError::MissingAnchor(_)) => return Ok(Verdict::Indeterminate(e)),
            Err(e) => return Ok(Verdict::Rejected(e)),
        };
        if self.policy.abandoned_issuer == AbandonedIssuer::Reject && abandoned(kel, &state.issuer)
        {
            return Ok(Verdict::Rejected(RegistryError::AbandonedIssuer(
                state.issuer,
            )));
        }
        Ok(Verdict::Valid {
            state,
            evidence: Evidence::Disclosure,
        })
    }
}

fn abandoned<D: EventDatabase>(kel: &EventStorage<D>, issuer: &IdentifierPrefix) -> bool {
    kel.get_state(issuer)
        .is_some_and(|state| state.is_abandoned())
}
