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
    event_message::{
        msg::KeriEvent,
        signature::{Signature, SignerData},
    },
    oobi_manager::storage::OobiStorageBackend,
    prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};
use said::SelfAddressingIdentifier;
use teliox::{
    ipex::{self, Admit, Grant, IpexError},
    registry::{
        AcdcBinding, Blinding, Disclosure, Pending, Policy, Presentation, RegistryIssuer,
        RegistryStore, Validator, Verdict,
    },
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
    /// The registry events kept here count with the disclosed ones, so a
    /// disclosure cut short of an update kept here is judged at that update.
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

/// IPEX: disclosing credentials to other identifiers and acknowledging
/// disclosures. A grant is made unsigned, its signing bytes signed by this
/// identifier's current keys, and finalized into the stream to deliver: the
/// registry events of the credential, then the signed grant.
impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// This identifier's signature on an exchange, bound to its latest
    /// establishment event.
    fn exchange_signature(&self, sig: SelfSigningPrefix) -> Result<Signature, ControllerError> {
        let seal = self
            .known_events
            .storage
            .get_last_establishment_event_seal(&self.id)
            .ok_or_else(|| ControllerError::UnknownIdentifierError)?;
        Ok(Signature::Transferable(
            SignerData::EventSeal(seal),
            vec![IndexedSignature::new_both_same(sig, 0)],
        ))
    }

    /// An unsigned grant of the presented credential to `recipient`.
    pub fn grant(
        &self,
        recipient: &IdentifierPrefix,
        message: &str,
        presentation: &Presentation,
    ) -> Grant {
        Grant::new(
            &self.id,
            recipient,
            message,
            presentation.acdc.clone(),
            presentation.disclosure.block.clone(),
        )
    }

    /// The stream to deliver for `grant` signed with `sig`: the registry
    /// events of `presentation`, then the signed grant.
    pub fn finalize_grant(
        &self,
        grant: Grant,
        presentation: &Presentation,
        sig: SelfSigningPrefix,
    ) -> Result<Vec<u8>, ControllerError> {
        let grant = grant.signed(vec![self.exchange_signature(sig)?]);
        ipex::grant_stream(&presentation.disclosure, &grant).map_err(ipex_error)
    }

    /// Reads a grant stream sent to this identifier, verifies the sender's
    /// signatures, and judges the credential it presents. The sender's and
    /// the credential issuer's KELs must be known here.
    pub fn receive_grant(
        &self,
        stream: &[u8],
        policy: &Policy,
    ) -> Result<(Grant, Presentation, Verdict), ControllerError> {
        let (presentation, grant) = ipex::parse_grant_stream(stream).map_err(ipex_error)?;
        if grant.exchange.data.recipient != self.id {
            return Err(ControllerError::OtherError(format!(
                "the grant is for {}, not {}",
                grant.exchange.data.recipient, self.id
            )));
        }
        grant
            .verify(&self.known_events.storage)
            .map_err(ipex_error)?;
        let verdict = self.accept_disclosure(
            &presentation.disclosure,
            Some(&presentation.binding()?),
            policy,
        )?;
        Ok((grant, presentation, verdict))
    }

    /// An unsigned admit of a grant sent to this identifier.
    pub fn admit(&self, grant: &Grant, message: &str) -> Result<Admit, ControllerError> {
        Admit::new(grant, message).map_err(ipex_error)
    }

    /// The admit signed with `sig`, to deliver to the grant's sender.
    pub fn finalize_admit(
        &self,
        admit: Admit,
        sig: SelfSigningPrefix,
    ) -> Result<Vec<u8>, ControllerError> {
        admit
            .signed(vec![self.exchange_signature(sig)?])
            .to_cesr()
            .map_err(ipex_error)
    }

    /// Reads an admit sent to this identifier and verifies its signatures.
    pub fn receive_admit(&self, bytes: &[u8]) -> Result<Admit, ControllerError> {
        let admit = Admit::parse(bytes).map_err(ipex_error)?;
        if admit.exchange.data.recipient != self.id {
            return Err(ControllerError::OtherError(format!(
                "the admit is for {}, not {}",
                admit.exchange.data.recipient, self.id
            )));
        }
        admit
            .verify(&self.known_events.storage)
            .map_err(ipex_error)?;
        Ok(admit)
    }
}

fn ipex_error(e: IpexError) -> ControllerError {
    match e {
        IpexError::Registry(e) => ControllerError::RegistryError(e),
        e => ControllerError::OtherError(e.to_string()),
    }
}
