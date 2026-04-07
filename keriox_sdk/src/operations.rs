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

use keri_core::event_message::signed_event_message::Notice;

use crate::{
    controller::Controller,
    error::{Error, Result},
    identifier::{Identifier, ActionRequired},
    types::{
        DelegationConfig, DelegationRequest, GroupConfig, IdentifierConfig, MultisigRequest,
        RotationConfig,
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
        let pk_data = keri_keyprovider::KeyProvider::public_key(self);
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

/// Create a new identifier (deprecated alias for [`create_identifier`]).
///
/// # Deprecated
/// Use [`create_identifier`] with an [`IdentifierConfig`] instead.
#[deprecated(since = "0.2.0", note = "use create_identifier with IdentifierConfig")]
pub async fn setup_identifier<S: SigningBackend + Clone + 'static>(
    controller: &Controller,
    signer: S,
    next_pk: BasicPrefix,
    witnesses: Vec<LocationScheme>,
    witness_threshold: u64,
    watchers: Vec<LocationScheme>,
) -> Result<Identifier> {
    let pks = vec![BasicPrefix::Ed25519(signer.public_key())];
    let npks = vec![next_pk];

    let inception_event = controller
        .incept(pks, npks, witnesses.clone(), witness_threshold)
        .await?;

    let sig = ed25519_sig(&signer, inception_event.as_bytes())?;
    let mut id = controller.finalize_incept(inception_event.as_bytes(), &sig)?;

    id.notify_witnesses().await?;

    for wit in &witnesses {
        if let IdentifierPrefix::Basic(wit_id) = &wit.eid {
            _query_mailbox(&mut id, &signer, wit_id).await?;
        }
        id.send_oobi_to_watcher(id.id(), &Oobi::Location(wit.clone()))
            .await?;
        if let IdentifierPrefix::Basic(wit_id) = &wit.eid {
            _query_mailbox(&mut id, &signer, wit_id).await?;
        }
    }

    for watch in &watchers {
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

/// Rotation with explicit positional args (deprecated alias for [`rotate`]).
///
/// # Deprecated
/// Use [`rotate`] with a [`RotationConfig`] instead.
#[deprecated(since = "0.2.0", note = "use rotate with RotationConfig")]
pub async fn rotate_identifier<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    current_signer: S,
    new_next_keys: Vec<BasicPrefix>,
    new_next_threshold: u64,
    witness_to_add: Vec<LocationScheme>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
) -> Result<()> {
    let current_keys = vec![BasicPrefix::Ed25519NT(current_signer.public_key())];

    let rotation_event = id
        .rotate(
            current_keys,
            new_next_keys,
            new_next_threshold,
            witness_to_add,
            witness_to_remove,
            witness_threshold,
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

/// Issue a credential — deprecated positional-arg alias for [`issue`].
///
/// # Deprecated
/// Use [`issue`] instead.
#[deprecated(since = "0.2.0", note = "use issue(id, signer, cred_said)")]
pub async fn issue_credential<S: SigningBackend + Clone + 'static>(
    identifier: &mut Identifier,
    cred_said: SelfAddressingIdentifier,
    km: S,
) -> Result<()> {
    issue(identifier, km, cred_said).await
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

/// Revoke a credential — deprecated positional-arg alias for [`revoke`].
///
/// # Deprecated
/// Use [`revoke`] instead.
#[deprecated(since = "0.2.0", note = "use revoke(id, signer, cred_said)")]
pub async fn revoke_credential<S: SigningBackend + Clone + 'static>(
    identifier: &mut Identifier,
    cred_said: &SelfAddressingIdentifier,
    km: S,
) -> Result<()> {
    revoke(identifier, km, cred_said).await
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

/// Create a delegated identifier (delegatee side, step 1 of 2).
///
/// Internally creates a temporary helper identifier, generates a DIP
/// (delegated inception) event, signs it, and sends the delegation request
/// to the delegator via witnesses.
///
/// The delegated identifier is **not** yet accepted — the delegator must
/// approve it first. After approval, call [`finalize_delegation`] with
/// the returned `Identifier` and prefix.
///
/// Returns `(temporary_identifier, delegated_prefix)`.
///
/// # Errors
/// - [`Error::Controller`] on event generation failures.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn create_delegated_identifier<S: SigningBackend + Clone + 'static>(
    db_path: PathBuf,
    signer: S,
    next_pk: BasicPrefix,
    config: DelegationConfig,
) -> Result<(Identifier, IdentifierPrefix)> {
    // Step 1: Create a temporary identifier (needed by incept_group).
    let temp_config = IdentifierConfig {
        witnesses: config.witnesses.clone(),
        witness_threshold: config.witness_threshold,
        watchers: vec![], // watchers configured after delegation is accepted
    };
    let mut temp_id = create_identifier(db_path, signer.clone(), next_pk, temp_config).await?;

    // Step 2: Extract witness BasicPrefixes for the delegated identifier.
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

    // Step 3: Generate delegated inception (DIP) + exchange messages.
    let (dip, exn_messages) = temp_id.incept_group(
        vec![],
        1,
        Some(1),
        Some(witness_ids),
        Some(config.witness_threshold),
        Some(config.delegator),
    )?;

    // Step 4: Sign and finalise.
    let sig_icp = ed25519_sig(&signer, dip.as_bytes())?;

    // The last exchange message is the delegation request to the delegator.
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

/// Complete the delegation process after the delegator approves (delegatee
/// side, step 2 of 2).
///
/// Saves the delegator's KEL into the local database, then queries the
/// delegated identifier's mailbox until the DIP event is accepted.
///
/// `delegator_kel` is the delegator's KEL (inception + receipts) obtained
/// out-of-band or via OOBI resolution.
///
/// # Errors
/// - [`Error::Mechanics`] on network or mailbox failures.
/// - [`Error::Signing`] if signing fails.
pub async fn finalize_delegation<S: SigningBackend + Clone + 'static>(
    temp_id: &mut Identifier,
    signer: &S,
    delegated_prefix: &IdentifierPrefix,
    delegator_kel: Vec<Notice>,
    witnesses: &[BasicPrefix],
) -> Result<()> {
    // Save the delegator's KEL events into local DB.
    for notice in &delegator_kel {
        temp_id.save_notice(notice)?;
    }

    // Query mailbox for the delegated identifier to get the delegating event.
    for witness in witnesses {
        _query_mailbox_for(temp_id, signer, delegated_prefix, witness).await?;
    }

    // Query again to get witness receipts (the DIP may now be accepted).
    for witness in witnesses {
        _query_mailbox_for(temp_id, signer, delegated_prefix, witness).await?;
    }

    Ok(())
}

// ── Multisig operations ──────────────────────────────────────────────────────

/// Create a multisig group identifier (initiator side).
///
/// Generates the group inception event, signs it with the caller's key,
/// and sends exchange messages to all other participants via witnesses.
///
/// The group identifier is **not** yet accepted — other participants must
/// co-sign via [`join_group`], and all participants must call
/// [`collect_group_signatures`] to finalise.
///
/// Returns the group `IdentifierPrefix`.
///
/// # Preconditions
/// - `id` must be a fully established individual identifier with witnesses.
/// - The caller must have resolved all participants' KELs (via watcher/OOBI).
///
/// # Errors
/// - [`Error::Controller`] if group inception generation fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn create_group_identifier<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    config: GroupConfig,
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
        config.participants,
        config.signature_threshold,
        config.next_keys_threshold,
        Some(witness_ids),
        Some(config.witness_threshold),
        config.delegator,
    )?;

    let sig_icp = ed25519_sig(signer, icp.as_bytes())?;

    // Sign each exchange message (one per participant, plus optional delegation).
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

/// Co-sign a multisig group event discovered in the mailbox (joiner side).
///
/// The `request` is obtained by calling [`query_multisig_requests`] or by
/// converting an [`ActionRequired::MultisigRequest`] into a
/// [`MultisigRequest`].
///
/// # Errors
/// - [`Error::EncodingError`] if event encoding fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn join_group<S: SigningBackend + Clone + 'static>(
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

/// Collect co-signatures and witness receipts for a group event.
///
/// Queries the group identifier's mailbox in two rounds (matching the
/// protocol requirement for signature collection followed by receipt
/// collection). Must be called by **all** participants after the group
/// event has been co-signed by enough participants.
///
/// After this call, verify acceptance with
/// `id.find_state(group_id)`.
///
/// # Errors
/// - [`Error::Mechanics`] on network or mailbox failures.
/// - [`Error::Signing`] if signing fails.
pub async fn collect_group_signatures<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    witnesses: &[BasicPrefix],
) -> Result<()> {
    // Round 1: collect co-signatures from other participants.
    for witness in witnesses {
        _query_mailbox_for(id, signer, group_id, witness).await?;
    }

    // Round 2: collect witness receipts.
    for witness in witnesses {
        _query_mailbox_for(id, signer, group_id, witness).await?;
    }

    Ok(())
}

/// Query this participant's mailbox for pending multisig requests.
///
/// Returns a list of [`MultisigRequest`] items found, filtering out
/// non-multisig actions. This is a convenience wrapper around
/// [`query_mailbox`] + [`MultisigRequest::try_from`].
///
/// # Errors
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn query_multisig_requests<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    witnesses: &[BasicPrefix],
) -> Result<Vec<MultisigRequest>> {
    let own_id = id.id().clone();
    let mut requests = vec![];
    for witness in witnesses {
        let actions = _query_mailbox_for(id, signer, &own_id, witness).await?;
        for action in actions {
            if let Ok(req) = MultisigRequest::try_from(action) {
                requests.push(req);
            }
        }
    }
    Ok(requests)
}
