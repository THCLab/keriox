//! ACDC 2.0 registries of an identifier: issuing and revoking credentials in
//! registries it runs, and judging the registries others disclose to it.
//!
//! Each credential has a registry of its own. Registry events are anchored
//! by an interaction event of this identifier: making them returns the
//! pending registry events and the `ixn` to sign, and
//! [`Identifier::finalize_registry_events`] publishes the signed `ixn` and
//! keeps the events, so a registry never runs ahead of its anchors. A group
//! finalizes the `ixn` with its members' signatures and then calls
//! [`Identifier::commit_registry_events`].

use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event::KeyEvent,
    event_message::msg::KeriEvent,
    oobi_manager::storage::OobiStorageBackend,
    prefix::SelfSigningPrefix,
};
use said::SelfAddressingIdentifier;
use teliox::registry::{
    AcdcBinding, Blinding, Disclosure, Pending, Policy, RegistryIssuer, RegistryStore, Validator,
    Verdict,
};

use crate::error::ControllerError;

use super::{mechanics::MechanicsError, Identifier};

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    fn registry_issuer(&self) -> RegistryIssuer<std::sync::Arc<T>> {
        RegistryIssuer::new(self.known_events.registries.clone())
    }

    fn anchoring(
        &self,
        pending: Vec<Pending>,
    ) -> Result<(Vec<Pending>, KeriEvent<KeyEvent>), ControllerError> {
        let seals = pending
            .iter()
            .map(Pending::seal)
            .collect::<Result<Vec<_>, _>>()?;
        let ixn = self.anchor_with_seal(&seals)?;
        Ok((pending, ixn))
    }

    /// A new registry of this identifier, for a credential still to be
    /// built naming it. Issue the credential with [`Self::issue_in`].
    pub fn incept_registry(&self) -> Result<Pending, ControllerError> {
        Ok(self.registry_issuer().incept(&self.id)?)
    }

    /// Issues `acdc` as the first update of the registry `inception` starts,
    /// and the `ixn` anchoring both.
    pub fn issue_in(
        &self,
        inception: Pending,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<(Vec<Pending>, KeriEvent<KeyEvent>), ControllerError> {
        let issued = self
            .registry_issuer()
            .issue_after(&inception, blinding, acdc)?;
        self.anchoring(vec![inception, issued])
    }

    /// The next update of `registry`, giving `acdc` the `state` with its
    /// block blinded as `blinding` says, and the `ixn` anchoring it.
    pub fn update_registry(
        &self,
        registry: &SelfAddressingIdentifier,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
        state: &str,
    ) -> Result<(Vec<Pending>, KeriEvent<KeyEvent>), ControllerError> {
        self.anchoring(vec![self
            .registry_issuer()
            .update(registry, blinding, acdc, state)?])
    }

    /// Revokes `acdc` in `registry`.
    pub fn revoke(
        &self,
        registry: &SelfAddressingIdentifier,
        blinding: &Blinding,
        acdc: &SelfAddressingIdentifier,
    ) -> Result<(Vec<Pending>, KeriEvent<KeyEvent>), ControllerError> {
        self.update_registry(registry, blinding, acdc, "revoked")
    }

    /// Publishes the signed `ixn` anchoring `pending`, then keeps `pending`.
    pub async fn finalize_registry_events(
        &mut self,
        pending: &[Pending],
        ixn: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        self.finalize_anchor(ixn, sig).await?;
        self.commit_registry_events(pending)
            .map_err(|e| MechanicsError::OtherError(e.to_string()))
    }

    /// Keeps registry events whose anchoring `ixn` was finalized, in order.
    pub fn commit_registry_events(&self, pending: &[Pending]) -> Result<(), ControllerError> {
        let issuer = self.registry_issuer();
        for event in pending {
            issuer.commit(event)?;
        }
        Ok(())
    }

    /// What a Discloser presents of a registry this identifier runs.
    pub fn registry_disclosure(
        &self,
        registry: &SelfAddressingIdentifier,
    ) -> Result<Disclosure, ControllerError> {
        Ok(self.registry_issuer().disclosure(registry)?)
    }

    /// Judges a disclosed registry against the Issuer's KEL as known here,
    /// and keeps it if it is valid. The Issuer's KEL must be known first.
    pub fn accept_disclosure(
        &self,
        disclosure: &Disclosure,
        acdc: Option<&AcdcBinding>,
        policy: &Policy,
    ) -> Result<Verdict, ControllerError> {
        let validator = Validator::new(self.known_events.registries.clone(), policy.clone());
        Ok(validator.accept(&self.known_events.storage, disclosure, acdc)?)
    }

    /// Judges a registry accepted before, against the Issuer's KEL as it is
    /// now known here.
    pub fn registry_verdict(
        &self,
        registry: &SelfAddressingIdentifier,
        acdc: Option<&AcdcBinding>,
        policy: &Policy,
    ) -> Result<Verdict, ControllerError> {
        let validator = Validator::new(self.known_events.registries.clone(), policy.clone());
        Ok(validator.state(&self.known_events.storage, registry, acdc)?)
    }
}
