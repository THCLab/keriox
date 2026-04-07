//! Higher-level compound operations for common KERI workflows.
//!
//! These functions combine multiple low-level steps (event generation,
//! signing, witness notification, mailbox queries) so callers don't need to
//! orchestrate individual calls. All signing is done internally with the
//! provided signer — callers never touch raw CESR prefix types.
//!
//! When the `keyprovider` feature is enabled, all functions accept
//! [`KeriSigner`](crate::keyprovider_adapter::KeriSigner) which can wrap
//! either a legacy `Signer` or any `KeyProvider` implementation.
//! Without the feature, they accept `Arc<Signer>`.
//!
//! For persistence of identifiers across sessions see [`crate::store`].
//! For signing arbitrary payloads see [`crate::signing`].

use std::path::PathBuf;

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme, Oobi, SelfSigningPrefix};
use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    prefix::IndexedSignature,
    query::mailbox::SignedMailboxQuery,
};


use crate::{
    controller::Controller,
    error::{Error, Result},
    identifier::{Identifier, ActionRequired},
    types::{
        DelegationConfig, DelegationRequest, IdentifierConfig, MultisigConfig, MultisigRequest,
        PendingRequest, RotationConfig,
    },
};

// ── Signer abstraction ────────────────────────────────────────────────────────

/// Trait abstracting what operations need from a signer.
///
/// Implemented for `Arc<Signer>` (always) and
/// `KeriSigner` (when the `keyprovider` feature is enabled).
/// Trait abstracting what operations need from any signer.
///
/// Implemented for `Arc<Signer>` (always) and
/// `KeriSigner` (when the `keyprovider` feature is enabled).
pub trait SigningBackend {
    /// Sign a message, returning raw signature bytes.
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>>;
    /// Return the public key.
    fn public_key(&self) -> keri_core::keys::PublicKey;
}

impl SigningBackend for std::sync::Arc<keri_core::signer::Signer> {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
            .map_err(|e| Error::Signing(e.to_string()))
    }

    fn public_key(&self) -> keri_core::keys::PublicKey {
        keri_core::signer::Signer::public_key(self)
    }
}

#[cfg(feature = "keyprovider")]
impl SigningBackend for crate::keyprovider_adapter::KeriSigner {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data)
    }

    fn public_key(&self) -> keri_core::keys::PublicKey {
        self.public_key()
    }
}

#[cfg(feature = "keyprovider")]
impl SigningBackend for std::sync::Arc<dyn keri_keyprovider::KeyProvider> {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.sign(data).await
            })
        })
        .map_err(|e| Error::Signing(e.to_string()))
    }

    fn public_key(&self) -> keri_core::keys::PublicKey {
        let pk_data = (**self).public_key();
        keri_core::keys::PublicKey::new(pk_data.bytes.clone())
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

pub(crate) fn ed25519_sig(signer: &dyn SigningBackend, data: &[u8]) -> Result<SelfSigningPrefix> {
    let bytes = signer.sign_data(data)?;
    Ok(SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        bytes,
    ))
}

// ── Public compound operations ────────────────────────────────────────────────

/// Create a new identifier and return it ready to use.
///
/// Performs the full inception flow:
/// 1. Generates an inception event with the given keys and witness config.
/// 2. Signs + finalises it.
/// 3. Notifies witnesses.
/// 4. Queries each witness mailbox.
/// 5. Sends witness OOBIs to watchers and configures each watcher.
///
/// # Errors
/// - [`Error::Controller`] if event generation or finalisation fails.
/// - [`Error::Mechanics`] if witness notification or mailbox queries fail.
/// - [`Error::Signing`] if the signer fails to produce a signature.
pub async fn create_identifier<S: SigningBackend + Clone + 'static>(
    db_path: std::path::PathBuf,
    signer: S,
    next_pk: BasicPrefix,
    config: IdentifierConfig,
) -> Result<Identifier> {
    let controller = Controller::new(db_path)?;
    let pks = vec![BasicPrefix::Ed25519(signer.public_key())];
    let npks = vec![next_pk];

    let inception_event = controller
        .incept(pks, npks, config.witnesses.clone(), config.witness_threshold)
        .await?;

    let sig = ed25519_sig(&signer, inception_event.as_bytes())?;
    let mut id = controller.finalize_incept(inception_event.as_bytes(), &sig)?;

    id.notify_witnesses().await?;

    for wit in &config.witnesses {
        if let IdentifierPrefix::Basic(wit_id) = &wit.eid {
            _query_mailbox(&mut id, &signer, wit_id).await?;
        }
        id.send_oobi_to_watcher(id.id(), &Oobi::Location(wit.clone()))
            .await?;
        if let IdentifierPrefix::Basic(wit_id) = &wit.eid {
            _query_mailbox(&mut id, &signer, wit_id).await?;
        }
    }

    for watch in &config.watchers {
        add_watcher(&mut id, &signer, watch).await?;
    }

    Ok(id)
}

/// Add and configure a watcher for an identifier.
///
/// Resolves the watcher's OOBI, generates an `end_role_add` reply, signs it,
/// and sends it to the watcher.
///
/// # Errors
/// - [`Error::Mechanics`] if OOBI resolution or the network call fails.
/// - [`Error::Signing`] if signing the reply fails.
pub async fn add_watcher<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    watcher_oobi: &LocationScheme,
) -> Result<()> {
    id.resolve_oobi(&Oobi::Location(watcher_oobi.clone())).await?;
    let rpy = id.add_watcher(watcher_oobi.eid.clone())?;
    let sig = ed25519_sig(km, rpy.as_bytes())?;
    id.finalize_add_watcher(rpy.as_bytes(), sig).await?;
    Ok(())
}

/// Rotate keys, notify witnesses, and query mailboxes.
///
/// Signs the rotation event with `current_signer`, sends it to witnesses,
/// then queries each witness mailbox to process the receipts.
///
/// # Errors
/// - [`Error::Controller`] if rotation event generation fails.
/// - [`Error::Mechanics`] if witness notification or mailbox queries fail.
/// - [`Error::Signing`] if signing fails.
pub async fn rotate<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    current_signer: S,
    config: RotationConfig,
) -> Result<()> {
    let current_keys = vec![BasicPrefix::Ed25519NT(current_signer.public_key())];
    let new_next_keys = vec![config.new_next_pk];

    let rotation_event = id
        .rotate(
            current_keys,
            new_next_keys,
            1,
            config.witness_to_add,
            config.witness_to_remove,
            config.witness_threshold,
        )
        .await?;

    let sig = ed25519_sig(&current_signer, rotation_event.as_bytes())?;
    id.finalize_rotate(rotation_event.as_bytes(), sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in witnesses {
        _query_mailbox(id, &current_signer, &witness).await?;
    }

    Ok(())
}

/// Incept a credential registry and return its identifier.
///
/// Generates a `vcp` event, anchors it with an `ixn`, signs, notifies
/// witnesses and backers, and queries mailboxes. After this call the
/// identifier's `registry_id()` is set.
///
/// # Errors
/// - [`Error::Controller`] if registry inception or encoding fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn incept_registry<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
) -> Result<IdentifierPrefix> {
    let (reg_id, ixn) = id.incept_registry()?;
    let encoded_ixn = ixn
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = ed25519_sig(&signer, &encoded_ixn)?;
    id.finalize_anchor(&encoded_ixn, sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &witnesses {
        _query_mailbox(id, &signer, witness).await?;
    }

    id.notify_backers().await?;

    Ok(reg_id)
}

/// Issue a credential (TEL `iss` + anchor `ixn` + witness/backer notification).
///
/// After this call the credential identified by `credential_said` is in the
/// `Issued` state in the local TEL. Witnesses and backers are notified.
///
/// # Errors
/// - [`Error::Controller`] if event generation or encoding fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn issue<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    credential_said: SelfAddressingIdentifier,
) -> Result<()> {
    let (_vc_id, ixn) = id.issue(credential_said)?;
    let encoded_ixn = ixn
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = ed25519_sig(&signer, &encoded_ixn)?;
    id.finalize_anchor(&encoded_ixn, sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id
        .find_state(id.id())?
        .witness_config
        .witnesses;
    for witness in &witnesses {
        _query_mailbox(id, &signer, witness).await?;
    }

    id.notify_backers().await?;

    Ok(())
}

/// Revoke a credential (TEL `rev` + anchor `ixn` + witness/backer notification).
///
/// After this call the credential identified by `credential_said` is in the
/// `Revoked` state in the local TEL.
///
/// # Errors
/// - [`Error::Controller`] if event generation fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn revoke<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    credential_said: &SelfAddressingIdentifier,
) -> Result<()> {
    let ixn = id.revoke(credential_said)?;
    let sig = ed25519_sig(&signer, &ixn)?;
    id.finalize_anchor(&ixn, sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id
        .find_state(id.id())?
        .witness_config
        .witnesses;
    for witness in &witnesses {
        _query_mailbox(id, &signer, witness).await?;
    }

    id.notify_backers().await?;

    Ok(())
}

/// Sign and send mailbox queries to a single witness; return the signed queries.
///
/// This is an internal helper used by other operations in this module. It is
/// also useful when you want to pull updates from a specific witness without
/// doing a full operation.
///
/// # Errors
/// - [`Error::Mechanics`] on network or processing failures.
/// - [`Error::Signing`] if signing fails.
/// - [`Error::EncodingError`] if query encoding fails.
pub async fn query_mailbox<S: SigningBackend>(
    id: &mut Identifier,
    km: S,
    witness_id: &BasicPrefix,
) -> Result<Vec<SignedMailboxQuery>> {
    _query_mailbox(id, &km, witness_id).await
}

// Private implementation to avoid name collision with Identifier::query_mailbox.
async fn _query_mailbox<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    witness_id: &BasicPrefix,
) -> Result<Vec<SignedMailboxQuery>> {
    let mut out = vec![];
    for qry in id.query_mailbox(id.id(), &[witness_id.clone()])? {
        let encoded = qry.encode().map_err(|e| Error::EncodingError(e.to_string()))?;
        let sig = SelfSigningPrefix::Ed25519Sha512(km.sign_data(&encoded)?);
        let signatures = vec![IndexedSignature::new_both_same(sig.clone(), 0)];
        let signed_qry =
            SignedMailboxQuery::new_trans(qry.clone(), id.id().clone(), signatures);
        id.finalize_query_mailbox(vec![(qry, sig)]).await?;
        out.push(signed_qry);
    }
    Ok(out)
}

/// Like `_query_mailbox` but queries for an arbitrary identifier (not just
/// the identifier's own prefix). Returns any `ActionRequired` items.
async fn _query_mailbox_for<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    about: &IdentifierPrefix,
    witness_id: &BasicPrefix,
) -> Result<Vec<ActionRequired>> {
    let mut actions = vec![];
    for qry in id.query_mailbox(about, &[witness_id.clone()])? {
        let encoded = qry
            .encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let sig = SelfSigningPrefix::Ed25519Sha512(km.sign_data(&encoded)?);
        let result = id.finalize_query_mailbox(vec![(qry, sig)]).await?;
        actions.extend(result);
    }
    Ok(actions)
}

// ── Delegation operations ────────────────────────────────────────────────────

/// Approve a pending delegation request (delegator side).
///
/// Signs the delegating IXN event, notifies witnesses, queries the mailbox
/// for receipts, and sends the exchange message (approval notification) to
/// the delegatee via witnesses.
///
/// The `request` is typically obtained by calling
/// [`query_mailbox`] and converting the resulting
/// [`ActionRequired::DelegationRequest`] into a [`DelegationRequest`].
///
/// # Errors
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
/// - [`Error::EncodingError`] if event encoding fails.
pub async fn approve_delegation<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    request: DelegationRequest,
) -> Result<()> {
    let encoded_ixn = request
        .delegating_event
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let encoded_exn = request
        .exchange
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    let sig_ixn = ed25519_sig(signer, &encoded_ixn)?;

    // Finalise the delegating IXN.
    id.finalize_group_event(&encoded_ixn, sig_ixn.clone(), vec![])
        .await?;
    id.notify_witnesses().await?;

    // Query mailbox for IXN receipts.
    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &witnesses {
        _query_mailbox(id, signer, witness).await?;
    }

    // Send exchange (approval) to delegatee via witnesses.
    let sig_exn = ed25519_sig(signer, &encoded_exn)?;
    let data_signature = IndexedSignature::new_both_same(sig_ixn, 0);
    let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
    id.finalize_exchange(&encoded_exn, exn_index_sig, data_signature)
        .await?;

    Ok(())
}

// ── Multisig operations ──────────────────────────────────────────────────────

/// Request a delegated identifier (delegatee side, step 1 of 2).
///
/// Sends a delegation request to the delegator specified in `config`.
/// The returned identifier is **not** yet accepted — the delegator must
/// approve it first (see [`approve_delegation`]).
///
/// After approval, call [`complete_delegation`] with the returned values.
///
/// Returns `(identifier_handle, delegated_prefix)`.
///
/// # Errors
/// - [`Error::Controller`] on event generation failures.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn request_delegation<S: SigningBackend + Clone + 'static>(
    db_path: PathBuf,
    signer: S,
    next_pk: BasicPrefix,
    config: DelegationConfig,
) -> Result<(Identifier, IdentifierPrefix)> {
    // Create a temporary identifier (needed by incept_group).
    let temp_config = IdentifierConfig {
        witnesses: config.witnesses.clone(),
        witness_threshold: config.witness_threshold,
        watchers: vec![], // watchers configured after delegation is accepted
    };
    let mut temp_id = create_identifier(db_path, signer.clone(), next_pk, temp_config).await?;

    // Extract witness BasicPrefixes for the delegated identifier.
    let witness_ids: Vec<BasicPrefix> = config
        .witnesses
        .iter()
        .filter_map(|w| {
            if let IdentifierPrefix::Basic(b) = &w.eid {
                Some(b.clone())
            } else {
                None
            }
        })
        .collect();

    // Generate delegated inception (DIP) + exchange messages.
    let (dip, exn_messages) = temp_id.incept_group(
        vec![],
        1,
        Some(1),
        Some(witness_ids),
        Some(config.witness_threshold),
        Some(config.delegator),
    )?;

    // Sign and finalise.
    let sig_icp = ed25519_sig(&signer, dip.as_bytes())?;

    let delegation_exn = exn_messages
        .last()
        .ok_or_else(|| Error::DelegationError("no exchange message generated".into()))?;
    let sig_exn = ed25519_sig(&signer, delegation_exn.as_bytes())?;
    let exn_index_sig = temp_id.sign_with_index(sig_exn, 0)?;

    let delegated_prefix = temp_id
        .finalize_group_incept(
            dip.as_bytes(),
            sig_icp,
            vec![(delegation_exn.as_bytes().to_vec(), exn_index_sig)],
        )
        .await?;

    Ok((temp_id, delegated_prefix))
}

/// Complete the delegation after the delegator has approved (delegatee
/// side, step 2 of 2).
///
/// Retrieves the delegator's key event log from the local database
/// and queries the delegated identifier's mailbox to finalise acceptance.
///
/// # Preconditions
/// The delegator's OOBI must have been resolved beforehand so that their
/// key event log is available locally (e.g. via
/// `identifier.resolve_oobi(&delegator_oobi)`).
///
/// # Errors
/// - [`Error::DelegatorKelNotAvailable`] if the delegator's events are
///   not in the local database. Resolve the delegator's OOBI first.
/// - [`Error::NoWitnesses`] if the identifier has no witnesses configured.
/// - [`Error::Mechanics`] on network or mailbox failures.
/// - [`Error::Signing`] if signing fails.
pub async fn complete_delegation<S: SigningBackend + Clone + 'static>(
    temp_id: &mut Identifier,
    signer: &S,
    delegated_prefix: &IdentifierPrefix,
    delegator_id: &IdentifierPrefix,
) -> Result<()> {
    // Get witnesses from identifier state.
    let witnesses: Vec<BasicPrefix> = temp_id.witnesses().collect();
    if witnesses.is_empty() {
        return Err(Error::NoWitnesses(temp_id.id().clone()));
    }

    // Get delegator's KEL from local DB.
    let delegator_kel = temp_id
        .get_kel(delegator_id)
        .ok_or_else(|| Error::DelegatorKelNotAvailable(delegator_id.clone()))?;

    // Save the delegator's KEL notices into local DB.
    for notice in &delegator_kel {
        temp_id.save_notice(notice)?;
    }

    // Query mailbox for the delegated identifier (two rounds).
    for witness in &witnesses {
        _query_mailbox_for(temp_id, signer, delegated_prefix, witness).await?;
    }
    for witness in &witnesses {
        _query_mailbox_for(temp_id, signer, delegated_prefix, witness).await?;
    }

    Ok(())
}

/// Create a multisig identifier (initiator side).
///
/// Generates the group inception event, signs it, and sends invitations
/// to all other members via witnesses. The identifier is **not** yet
/// accepted — other members must co-sign via [`accept_multisig`], and
/// all members must call [`sync_multisig`] to finalise.
///
/// Returns the multisig `IdentifierPrefix`.
///
/// # Preconditions
/// - `id` must be a fully established individual identifier with witnesses.
/// - The caller must have resolved all members' OOBIs.
///
/// # Errors
/// - [`Error::Controller`] if event generation fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn create_multisig<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    config: MultisigConfig,
) -> Result<IdentifierPrefix> {
    let witness_ids: Vec<BasicPrefix> = config
        .witnesses
        .iter()
        .filter_map(|w| {
            if let IdentifierPrefix::Basic(b) = &w.eid {
                Some(b.clone())
            } else {
                None
            }
        })
        .collect();

    let (icp, exn_messages) = id.incept_group(
        config.members,
        config.threshold,
        Some(config.threshold),
        Some(witness_ids),
        Some(config.witness_threshold),
        config.delegator,
    )?;

    let sig_icp = ed25519_sig(signer, icp.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = ed25519_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    let group_prefix = id
        .finalize_group_incept(icp.as_bytes(), sig_icp, exchange_pairs)
        .await?;

    Ok(group_prefix)
}

/// Accept a multisig invitation discovered in the mailbox (joiner side).
///
/// Co-signs the group event and forwards the signature to other members
/// via witnesses.
///
/// The `request` is obtained from [`poll_pending_requests`] or by
/// converting an `ActionRequired::MultisigRequest`.
///
/// # Errors
/// - [`Error::EncodingError`] if event encoding fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn accept_multisig<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    request: MultisigRequest,
) -> Result<()> {
    let encoded_event = request
        .event
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let encoded_exn = request
        .exchange
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    let sig_event = ed25519_sig(signer, &encoded_event)?;
    let sig_exn = ed25519_sig(signer, &encoded_exn)?;
    let exn_index_sig = id.sign_with_index(sig_exn, 0)?;

    id.finalize_group_event(
        &encoded_event,
        sig_event,
        vec![(encoded_exn, exn_index_sig)],
    )
    .await?;

    Ok(())
}

/// Synchronise the multisig identifier state.
///
/// Queries the multisig identifier's mailbox to collect co-signatures
/// from other members and witness receipts. Must be called by **all**
/// members after enough co-signatures have been submitted.
///
/// After this call, verify acceptance with
/// `id.find_state(multisig_id)`.
///
/// # Errors
/// - [`Error::NoWitnesses`] if the identifier has no witnesses configured.
/// - [`Error::Mechanics`] on network or mailbox failures.
/// - [`Error::Signing`] if signing fails.
pub async fn sync_multisig<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    multisig_id: &IdentifierPrefix,
) -> Result<()> {
    let witnesses: Vec<BasicPrefix> = id.witnesses().collect();
    if witnesses.is_empty() {
        return Err(Error::NoWitnesses(id.id().clone()));
    }

    // Round 1: collect co-signatures from other members.
    for witness in &witnesses {
        _query_mailbox_for(id, signer, multisig_id, witness).await?;
    }

    // Round 2: collect witness receipts.
    for witness in &witnesses {
        _query_mailbox_for(id, signer, multisig_id, witness).await?;
    }

    Ok(())
}

/// Poll for pending delegation or multisig requests in this
/// identifier's mailbox.
///
/// Returns all discovered requests as [`PendingRequest`] items. Use
/// [`PendingRequest::into_delegation`] or
/// [`PendingRequest::into_multisig`] to extract the specific type and
/// pass it to [`approve_delegation`] or [`accept_multisig`].
///
/// # Errors
/// - [`Error::NoWitnesses`] if the identifier has no witnesses configured.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn poll_pending_requests<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
) -> Result<Vec<PendingRequest>> {
    let own_id = id.id().clone();
    let witnesses: Vec<BasicPrefix> = id.witnesses().collect();
    if witnesses.is_empty() {
        return Err(Error::NoWitnesses(own_id));
    }
    let mut requests = vec![];
    for witness in &witnesses {
        let actions = _query_mailbox_for(id, signer, &own_id, witness).await?;
        for action in actions {
            if let Ok(req) = PendingRequest::try_from(action) {
                requests.push(req);
            }
        }
    }
    Ok(requests)
}
