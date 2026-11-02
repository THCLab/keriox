//! Credentials and their registries: issuing and revoking ACDC 2.0
//! credentials, presenting them, and judging what others present.
//!
//! Each credential has a registry of its own: a registry inception and the
//! issuance are anchored together by one interaction event, and every
//! later update (revocation, re-blinding) by another. The holder presents
//! the credential with its registry ([`Presentation`]); a verifier judges
//! that presentation against the issuer's KEL. Nothing is looked up on the
//! network: the state is the state presented.
//!
//! The [`Blinding`] of a registry is a secret: keep it with the issuer's
//! other secrets, and share it only with the holder, who needs it to tell
//! the state behind each blinded update.

use acdc::Acdc;
use keri_controller::IdentifierPrefix;
use said::SelfAddressingIdentifier;
use teliox::registry::{Blinding, Pending, Policy, Presentation, Verdict};

use crate::advanced::{
    error::{Error, Result},
    identifier::{Forward, Identifier},
    operations::{collect_receipts, finalize_group_anchor, wrap_sig, SigningBackend},
};

fn said(text: &str) -> Result<SelfAddressingIdentifier> {
    text.parse()
        .map_err(|_| Error::ParseError(format!("invalid SAID: {text}")))
}

/// Signs and publishes the `ixn` anchoring `pending`, keeps `pending`, and
/// collects the witnesses' receipts.
async fn anchor<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    pending: &[Pending],
    ixn: &keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
) -> Result<()> {
    let encoded = ixn
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = wrap_sig(signer, &encoded)?;
    id.finalize_registry_events(pending, &encoded, sig).await?;
    id.notify_witnesses().await?;
    for witness in &id.find_state(id.id())?.witness_config.witnesses {
        let own = id.id().clone();
        collect_receipts(id, signer, &own, witness).await?;
    }
    Ok(())
}

/// Issues a credential in a registry of its own. `build` makes the ACDC
/// from the SAID of its registry, which the ACDC should name (`rd`), and
/// must make it with this identifier as its issuer.
///
/// # Errors
/// - [`Error::Other`] if `build` fails or names another issuer.
/// - [`Error::Controller`] / [`Error::Mechanics`] on event or network
///   failures.
pub async fn issue<S, F>(
    id: &mut Identifier,
    signer: S,
    blinding: &Blinding,
    build: F,
) -> Result<Presentation>
where
    S: SigningBackend + Clone + 'static,
    F: FnOnce(&SelfAddressingIdentifier) -> std::result::Result<Acdc, acdc::error::Error>,
{
    let inception = id.incept_registry()?;
    let registry = inception.event.said()?;
    let acdc = build(&registry).map_err(|e| Error::Other(format!("credential: {e}")))?;
    if acdc.issuer() != id.id().to_string() {
        return Err(Error::Other(format!(
            "the credential names issuer {}, not {}",
            acdc.issuer(),
            id.id()
        )));
    }
    let (pending, ixn) = id.issue_in(inception, blinding, &said(acdc.said())?)?;
    anchor(id, &signer, &pending, &ixn).await?;
    presentation(id, acdc)
}

/// Gives the credential `acdc` the `state` in its registry, such as
/// `"revoked"`, and returns its presentation after the update.
///
/// # Errors
/// - [`Error::Other`] if the credential names no registry.
/// - [`Error::Controller`] / [`Error::Mechanics`] on event or network
///   failures.
pub async fn update<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    blinding: &Blinding,
    acdc: Acdc,
    state: &str,
) -> Result<Presentation> {
    let registry = registry_of(&acdc)?;
    let (pending, ixn) = id.update_registry(&registry, blinding, &said(acdc.said())?, state)?;
    anchor(id, &signer, &pending, &ixn).await?;
    presentation(id, acdc)
}

/// Revokes the credential `acdc`.
///
/// # Errors
/// As [`update`].
pub async fn revoke<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    blinding: &Blinding,
    acdc: Acdc,
) -> Result<Presentation> {
    update(id, signer, blinding, acdc, "revoked").await
}

fn registry_of(acdc: &Acdc) -> Result<SelfAddressingIdentifier> {
    said(
        acdc.registry()
            .ok_or_else(|| Error::Other(format!("credential {} names no registry", acdc.said())))?,
    )
}

/// The presentation of a credential this identifier issued: the ACDC with
/// its registry as it now stands.
///
/// # Errors
/// - [`Error::Other`] if the credential names no registry.
/// - [`Error::Controller`] if the registry is not kept here.
pub fn presentation(id: &Identifier, acdc: Acdc) -> Result<Presentation> {
    let disclosure = id.registry_disclosure(&registry_of(&acdc)?)?;
    Ok(Presentation { acdc, disclosure })
}

/// Judges a presented credential against its issuer's KEL as known here,
/// and keeps its registry if it is valid. Resolve the issuer's KEL first;
/// until its anchors are known the verdict is indeterminate. Registry
/// events kept here count with the presented ones, as in
/// [`Identifier::accept_disclosure`].
///
/// # Errors
/// - [`Error::Controller`] if the registry store fails.
pub fn verify(id: &Identifier, presentation: &Presentation, policy: &Policy) -> Result<Verdict> {
    let binding = presentation.binding()?;
    id.accept_disclosure(&presentation.disclosure, Some(&binding), policy)
}

/// Issues a credential from a group identifier, as the member who starts
/// it: the anchoring `ixn` goes to the other members to sign, and the
/// registry is kept by this member. Returns the presentation, the digest
/// of the anchoring `ixn`, and the forwards to deliver to the other
/// members.
///
/// # Errors
/// As [`issue`].
pub async fn issue_group<S, F>(
    group: &mut Identifier,
    member: &IdentifierPrefix,
    signer: &S,
    blinding: &Blinding,
    build: F,
) -> Result<(Presentation, SelfAddressingIdentifier, Vec<Forward>)>
where
    S: SigningBackend + Clone + 'static,
    F: FnOnce(&SelfAddressingIdentifier) -> std::result::Result<Acdc, acdc::error::Error>,
{
    let inception = group.incept_registry()?;
    let registry = inception.event.said()?;
    let acdc = build(&registry).map_err(|e| Error::Other(format!("credential: {e}")))?;
    if acdc.issuer() != group.id().to_string() {
        return Err(Error::Other(format!(
            "the credential names issuer {}, not the group {}",
            acdc.issuer(),
            group.id()
        )));
    }
    let (pending, ixn) = group.issue_in(inception, blinding, &said(acdc.said())?)?;
    let digest = ixn
        .digest()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let forwards = finalize_group_anchor(group, member, signer, &ixn).await?;
    group.commit_registry_events(&pending)?;
    Ok((presentation(group, acdc)?, digest, forwards))
}
