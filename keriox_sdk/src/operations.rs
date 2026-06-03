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
    actor::prelude::SelfAddressingIdentifier, prefix::IndexedSignature,
    query::mailbox::SignedMailboxQuery,
};

use crate::{
    controller::Controller,
    error::{Error, Result},
    identifier::{ActionRequired, Identifier},
    types::{
        DelegationConfig, DelegationRequest, GroupRotationConfig, IdentifierConfig,
        MultisigConfig, MultisigRequest, PendingRequest, RotationConfig,
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
    /// The CESR self-signing code matching this backend's algorithm.
    ///
    /// Implementations should return the variant whose raw signature byte
    /// layout matches what [`sign_data`] produces. Used to wrap raw signature
    /// bytes in the correct [`SelfSigningPrefix`] variant.
    fn signing_code(&self) -> cesrox::primitives::codes::self_signing::SelfSigning;
    /// The [`BasicPrefix`] variant for this backend's public key.
    ///
    /// `transferable = true` selects the rotation-capable variant
    /// (Ed25519 / ECDSAsecp256k1 / ECDSA256r1); `false` selects the
    /// non-transferable variant.
    fn basic_prefix(&self, transferable: bool) -> BasicPrefix;
}

impl SigningBackend for std::sync::Arc<keri_core::signer::Signer> {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.sign(data).map_err(|e| Error::Signing(e.to_string()))
    }

    fn public_key(&self) -> keri_core::keys::PublicKey {
        keri_core::signer::Signer::public_key(self)
    }

    fn signing_code(&self) -> cesrox::primitives::codes::self_signing::SelfSigning {
        keri_core::signer::Signer::signing_code(self)
    }

    fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        keri_core::signer::Signer::basic_prefix(self, transferable)
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

    fn signing_code(&self) -> cesrox::primitives::codes::self_signing::SelfSigning {
        self.signing_code()
    }

    fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        self.basic_prefix(transferable)
    }
}

#[cfg(feature = "keyprovider")]
impl SigningBackend for std::sync::Arc<dyn keri_keyprovider::KeyProvider> {
    fn sign_data(&self, data: &[u8]) -> Result<Vec<u8>> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { self.sign(data).await })
        })
        .map_err(|e| Error::Signing(e.to_string()))
    }

    fn public_key(&self) -> keri_core::keys::PublicKey {
        let pk_data = (**self).public_key();
        keri_core::keys::PublicKey::new(pk_data.bytes.clone())
    }

    fn signing_code(&self) -> cesrox::primitives::codes::self_signing::SelfSigning {
        crate::keyprovider_adapter::signing_code_for(self.algorithm())
    }

    fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        let pk = SigningBackend::public_key(self);
        crate::keyprovider_adapter::basic_prefix_for(self.algorithm(), pk, transferable)
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Sign `data` with `signer` and wrap the raw bytes in the [`SelfSigningPrefix`]
/// variant matching the signer's algorithm.
pub(crate) fn wrap_sig(signer: &dyn SigningBackend, data: &[u8]) -> Result<SelfSigningPrefix> {
    let bytes = signer.sign_data(data)?;
    Ok(SelfSigningPrefix::new(signer.signing_code(), bytes))
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
    create_identifier_with_controller(&controller, signer, next_pk, config).await
}

pub(crate) async fn create_identifier_with_controller<S: SigningBackend + Clone + 'static>(
    controller: &Controller,
    signer: S,
    next_pk: BasicPrefix,
    config: IdentifierConfig,
) -> Result<Identifier> {
    let pks = vec![signer.basic_prefix(true)];
    let npks = vec![next_pk];

    let inception_event = controller
        .incept(
            pks,
            npks,
            config.witnesses.clone(),
            config.witness_threshold,
        )
        .await?;

    let sig = wrap_sig(&signer, inception_event.as_bytes())?;
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
    id.resolve_oobi(&Oobi::Location(watcher_oobi.clone()))
        .await?;
    let rpy = id.add_watcher(watcher_oobi.eid.clone())?;
    let sig = wrap_sig(km, rpy.as_bytes())?;
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
    // Keys revealed by this rotation must use the same BasicPrefix variant
    // that the prior establishment event committed to (in next_keys_hashes).
    // The store always commits next-keys as non-transferable (since they're
    // a hash commitment, not yet a rotation-capable key), so reveal with NT
    // here too — otherwise the next-key-binding check on the verifier side
    // will reject the rotation.
    let current_keys = vec![current_signer.basic_prefix(false)];
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

    let sig = wrap_sig(&current_signer, rotation_event.as_bytes())?;
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
    let sig = wrap_sig(&signer, &encoded_ixn)?;
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
    let sig = wrap_sig(&signer, &encoded_ixn)?;
    id.finalize_anchor(&encoded_ixn, sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
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
    let sig = wrap_sig(&signer, &ixn)?;
    id.finalize_anchor(&ixn, sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
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
        let encoded = qry
            .encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let sig = SelfSigningPrefix::new(km.signing_code(), km.sign_data(&encoded)?);
        let signatures = vec![IndexedSignature::new_both_same(sig.clone(), 0)];
        let signed_qry = SignedMailboxQuery::new_trans(qry.clone(), id.id().clone(), signatures);
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
        let sig = SelfSigningPrefix::new(km.signing_code(), km.sign_data(&encoded)?);
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

    let sig_ixn = wrap_sig(signer, &encoded_ixn)?;

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
    let sig_exn = wrap_sig(signer, &encoded_exn)?;
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
        algorithm: config.algorithm,
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
    let sig_icp = wrap_sig(&signer, dip.as_bytes())?;

    let delegation_exn = exn_messages
        .last()
        .ok_or_else(|| Error::DelegationError("no exchange message generated".into()))?;
    let sig_exn = wrap_sig(&signer, delegation_exn.as_bytes())?;
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

// ── Out-of-band (witness-less) delegation ────────────────────────────────────

/// Build a delegated identifier locally and return the encoded `dip`
/// event for out-of-band transport to the delegator.
///
/// Same effect as [`request_delegation`]: the temporary identifier is
/// created, the `dip` is signed by the delegatee and applied locally
/// (escrowed pending the delegator's seal). The difference is that
/// this entry point also returns the raw CESR string of the `dip`,
/// so the caller can deliver it directly to the delegator over an
/// out-of-band channel (e.g. a peer-to-peer connection) instead of
/// the witness mailbox.
///
/// After the delegator returns the signed delegating `ixn`, call
/// [`finalize_delegation_with_seal`] on the returned identifier.
pub async fn build_delegation_request<S: SigningBackend + Clone + 'static>(
    db_path: PathBuf,
    signer: S,
    next_pk: BasicPrefix,
    config: DelegationConfig,
) -> Result<(Identifier, IdentifierPrefix, String)> {
    let temp_config = IdentifierConfig {
        witnesses: config.witnesses.clone(),
        witness_threshold: config.witness_threshold,
        watchers: vec![],
        algorithm: config.algorithm,
    };
    let mut temp_id = create_identifier(db_path, signer.clone(), next_pk, temp_config).await?;

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

    let (dip, exn_messages) = temp_id.incept_group(
        vec![],
        1,
        Some(1),
        Some(witness_ids),
        Some(config.witness_threshold),
        Some(config.delegator.clone()),
    )?;

    let sig_icp = wrap_sig(&signer, dip.as_bytes())?;

    let delegation_exn = exn_messages
        .last()
        .ok_or_else(|| Error::DelegationError("no exchange message generated".into()))?;
    let sig_exn = wrap_sig(&signer, delegation_exn.as_bytes())?;
    let exn_index_sig = temp_id.sign_with_index(sig_exn, 0)?;

    let delegated_prefix = temp_id
        .finalize_group_incept(
            dip.as_bytes(),
            sig_icp,
            vec![(delegation_exn.as_bytes().to_vec(), exn_index_sig)],
        )
        .await?;

    Ok((temp_id, delegated_prefix, dip))
}

/// Sign a delegating `ixn` on the delegator's KEL that anchors the
/// supplied delegated `dip` event's SAID. Returns the encoded
/// signed `ixn` (CESR stream including the indexed signature) for
/// out-of-band transport to the delegatee.
///
/// Works for both single-AID and multi-sig group delegators. For a
/// single-AID delegator pass `group_id = delegator_id.id()` and
/// `participants = vec![delegator_id.id().clone()]`. For a multi-sig
/// group pass the group AID and the full member list.
///
/// Does NOT call [`Identifier::notify_witnesses`] or any mailbox
/// helper — the caller is responsible for transport.
pub async fn build_delegation_approval<S: SigningBackend + Clone + 'static>(
    delegator_id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    delegated_dip_cesr: &str,
    participants: &[IdentifierPrefix],
) -> Result<String> {
    use keri_core::event::sections::seal::{EventSeal, Seal};
    use keri_core::event_message::cesr_adapter::{parse_event_type, EventType};
    use keri_core::event_message::signed_event_message::Notice;

    let parsed = parse_event_type(delegated_dip_cesr.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let dip_event = match parsed {
        EventType::KeyEvent(ke) => ke,
        _ => {
            return Err(Error::EncodingError(
                "delegated event is not a key event".into(),
            ))
        }
    };

    let delegated_prefix = dip_event.data.get_prefix();
    let dip_sn = dip_event.data.get_sn();
    let dip_digest = dip_event
        .digest()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let event_seal = Seal::Event(EventSeal::new(delegated_prefix, dip_sn, dip_digest));

    let (ixn_cesr, exn_messages) =
        delegator_id.anchor_group_with_seals(group_id, &[event_seal], participants)?;

    let sig_ixn = wrap_sig(signer, ixn_cesr.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = delegator_id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    delegator_id
        .finalize_group_event(ixn_cesr.as_bytes(), sig_ixn.clone(), exchange_pairs)
        .await?;

    let group_state = delegator_id.find_state(group_id)?;
    let own_pk = delegator_id
        .find_state(delegator_id.id())?
        .current
        .public_keys
        .into_iter()
        .next()
        .ok_or_else(|| Error::Other("delegator member state has no public key".into()))?;
    let own_idx = group_state
        .current
        .public_keys
        .iter()
        .position(|pk| pk == &own_pk)
        .ok_or_else(|| Error::Other("delegator member key not in group key set".into()))?
        as u16;

    let parsed_ixn = parse_event_type(ixn_cesr.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let ixn_keyevent = match parsed_ixn {
        EventType::KeyEvent(ke) => ke,
        _ => return Err(Error::EncodingError("ixn is not a key event".into())),
    };
    let indexed_sig = IndexedSignature::new_both_same(sig_ixn, own_idx);
    let signed = ixn_keyevent.sign(vec![indexed_sig], None, None);
    let encoded = keri_core::event_message::signed_event_message::Message::Notice(Notice::Event(
        signed,
    ))
    .to_cesr()
    .map_err(|e| Error::EncodingError(e.to_string()))?;
    String::from_utf8(encoded).map_err(|e| Error::EncodingError(e.to_string()))
}

/// Build the unsigned delegating `ixn` event that anchors the supplied
/// delegated `dip` event's SAID, plus the exchange messages addressed
/// to every other group member. Unlike [`build_delegation_approval`]
/// the event is **not** signed, **not** saved, and **not** broadcast;
/// the returned `ixn_cesr` is the wire form the cosign coordinator
/// circulates so each Identity-AID member can produce their own
/// [`IndexedSignature`].
///
/// Use this entry point when the delegator is a k-of-N multi-sig
/// group and the delegating `ixn` must be cosigned before publication.
/// After the threshold of votes is collected, call
/// [`finalize_delegation_ixn_multi`] to assemble the signed event,
/// save it to the local KEL, and queue witness notification.
///
/// Returns `(unsigned_ixn_cesr, exn_messages_for_other_members)`.
pub fn build_delegation_ixn_unsigned(
    delegator_id: &mut Identifier,
    group_id: &IdentifierPrefix,
    delegated_dip_cesr: &str,
    participants: &[IdentifierPrefix],
) -> Result<(String, Vec<String>)> {
    use keri_core::event::sections::seal::{EventSeal, Seal};
    use keri_core::event_message::cesr_adapter::{parse_event_type, EventType};

    let parsed = parse_event_type(delegated_dip_cesr.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let dip_event = match parsed {
        EventType::KeyEvent(ke) => ke,
        _ => {
            return Err(Error::EncodingError(
                "delegated event is not a key event".into(),
            ))
        }
    };
    let delegated_prefix = dip_event.data.get_prefix();
    let dip_sn = dip_event.data.get_sn();
    let dip_digest = dip_event
        .digest()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let event_seal = Seal::Event(EventSeal::new(delegated_prefix, dip_sn, dip_digest));

    let (ixn_cesr, exn_messages) =
        delegator_id.anchor_group_with_seals(group_id, &[event_seal], participants)?;
    Ok((ixn_cesr, exn_messages))
}

/// Finalise a multi-sig delegating `ixn` once the threshold of
/// [`IndexedSignature`] votes has been collected. Mirrors the way
/// [`Identifier::finalize_rotate_multi`] is used for cosigned `rot`
/// events. Saves the assembled event to the local KEL and queues
/// witness notification (call [`publish_event_and_collect_receipts`]
/// after this to push the event to witnesses and gather receipts).
pub async fn finalize_delegation_ixn_multi(
    delegator_id: &mut Identifier,
    ixn_event_cesr: &[u8],
    sigs: Vec<IndexedSignature>,
) -> Result<()> {
    delegator_id.finalize_anchor_multi(ixn_event_cesr, sigs).await
}

/// Push every event currently queued via `to_notify` to the
/// caller-identifier's witnesses and then poll each witness mailbox
/// once for receipts. Wraps the witness/mailbox legs of
/// [`approve_delegation`] so other callers (notably the cosigned
/// delegation flow) can reuse them without duplicating the loop.
pub async fn publish_event_and_collect_receipts<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
) -> Result<()> {
    id.notify_witnesses().await?;
    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &witnesses {
        _query_mailbox(id, signer, witness).await?;
    }
    Ok(())
}

/// Finalise the delegated AID by ingesting the delegator's signed
/// delegating `ixn` arriving out-of-band.
///
/// The CESR stream must include the delegator's signature(s) attached
/// to the `ixn` (as produced by [`build_delegation_approval`]). On
/// success the previously-escrowed `dip` in the local DB is accepted
/// by the processor and the delegated AID's KEL is complete.
pub async fn finalize_delegation_with_seal(
    temp_id: &Identifier,
    delegator_seal_cesr: &str,
) -> Result<()> {
    use keri_core::actor::parse_notice_stream;
    let notices = parse_notice_stream(delegator_seal_cesr.as_bytes())
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    if notices.is_empty() {
        return Err(Error::EncodingError(
            "no notices found in delegator seal stream".into(),
        ));
    }
    for notice in &notices {
        temp_id.save_notice(notice)?;
    }
    Ok(())
}

// ── Group KEL anchor ─────────────────────────────────────────────────────────

/// Anchor SAID seals on an established group AID's KEL as an `ixn`
/// event.
///
/// For a 1-of-N group the caller's signature alone finalises the
/// event. For k-of-N (k ≥ 2) other members complete the event via
/// [`accept_multisig`] + [`sync_multisig`]; the joiner-side flow is
/// unchanged because the underlying group-event finalisation is
/// event-type agnostic.
///
/// `participants` is the full member list of the group. For a
/// 1-of-N group the caller is the only member needed; the list is
/// still used to route exchange messages to other members.
///
/// Notifies witnesses and queries mailboxes when configured.
pub async fn anchor_group<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    anchors: &[SelfAddressingIdentifier],
    participants: &[IdentifierPrefix],
) -> Result<()> {
    let (ixn_cesr, exn_messages) = id.anchor_group(group_id, anchors, participants)?;

    let sig_ixn = wrap_sig(signer, ixn_cesr.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    id.finalize_group_event(ixn_cesr.as_bytes(), sig_ixn, exchange_pairs)
        .await?;
    id.notify_witnesses().await?;

    let caller_witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &caller_witnesses {
        _query_mailbox(id, signer, witness).await?;
    }
    let group_witnesses = id.find_state(group_id)?.witness_config.witnesses;
    for witness in &group_witnesses {
        _query_mailbox_for(id, signer, group_id, witness).await?;
    }

    Ok(())
}

/// Out-of-band variant of [`anchor_group`]: build the `ixn` event,
/// sign it locally, and return the event + per-co-signer exchange
/// messages as CESR strings for transport. Co-signers reconstruct a
/// [`MultisigRequest`] via [`MultisigRequest::from_cesr`] and call
/// [`accept_multisig`].
///
/// Does NOT call [`Identifier::notify_witnesses`] or any mailbox
/// helper. The caller's signature is still applied locally.
pub async fn build_group_anchor<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    anchors: &[SelfAddressingIdentifier],
    participants: &[IdentifierPrefix],
) -> Result<(String, Vec<String>)> {
    let (ixn_cesr, exn_messages) = id.anchor_group(group_id, anchors, participants)?;

    let sig_ixn = wrap_sig(signer, ixn_cesr.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    id.finalize_group_event(ixn_cesr.as_bytes(), sig_ixn, exchange_pairs)
        .await?;

    Ok((ixn_cesr, exn_messages))
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

    let sig_icp = wrap_sig(signer, icp.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    let group_prefix = id
        .finalize_group_incept(icp.as_bytes(), sig_icp, exchange_pairs)
        .await?;

    Ok(group_prefix)
}

/// Rotate the keys of an established multisig (group) identifier.
///
/// Builds a `rot` event against `group_id`, signs it with the caller's
/// `signer`, signs and forwards an exchange message to every other
/// remaining member, finalises the local state, and synchronises with
/// witnesses on both the caller's and the group's mailbox planes.
///
/// `config.new_participants` is the full post-rotation member set. The
/// caller (the local identifier) does not need to appear in it
/// (self-eviction is permitted) but must currently be a member of the
/// group's key set.
///
/// When `config.new_signature_threshold > 1` this call only contributes
/// the caller's signature; remaining co-signers complete the rotation
/// via [`accept_multisig`] (which already handles both inception and
/// rotation events) followed by [`sync_multisig`] on every member.
///
/// Removal and key refresh are supported. Adding a member whose
/// next-key digest was not pre-committed in the prior establishment
/// event is rejected by KERI verifiers; that scenario is out of scope.
///
/// # Errors
/// - [`Error::Controller`] if event generation or threshold validation fails.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn rotate_group<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    config: GroupRotationConfig,
) -> Result<()> {
    let (rot_event, exn_messages) = id
        .rotate_group(
            group_id,
            config.new_participants,
            config.new_signature_threshold,
            config.new_next_threshold,
            config.witness_to_add,
            config.witness_to_remove,
            config.witness_threshold,
        )
        .await?;

    let sig_rot = wrap_sig(signer, rot_event.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    id.finalize_group_event(rot_event.as_bytes(), sig_rot, exchange_pairs)
        .await?;
    id.notify_witnesses().await?;

    let caller_witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &caller_witnesses {
        _query_mailbox(id, signer, witness).await?;
    }
    let group_witnesses = id.find_state(group_id)?.witness_config.witnesses;
    for witness in &group_witnesses {
        _query_mailbox_for(id, signer, group_id, witness).await?;
    }

    Ok(())
}

/// Accept a pending group event discovered in the mailbox (joiner side).
///
/// Handles both group inceptions and group rotations: the underlying
/// `finalize_group_event` is event-type agnostic and the index-discovery
/// helper dispatches on event-data variant.
///
/// Co-signs the event and forwards the signature to other members via
/// witnesses. The `request` is obtained from [`poll_pending_requests`]
/// or by converting an `ActionRequired::MultisigRequest`.
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

    let sig_event = wrap_sig(signer, &encoded_event)?;
    let sig_exn = wrap_sig(signer, &encoded_exn)?;
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

// ── String-accepting convenience variants ────────────────────────────────────

/// Like [`issue`], but accepts the credential SAID as a `&str`.
///
/// Parses the string into a [`SelfAddressingIdentifier`] internally.
///
/// # Errors
/// - [`Error::ParseError`] if `credential_said` is not a valid SAID.
/// - All errors from [`issue`].
pub async fn issue_str<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    credential_said: &str,
) -> Result<()> {
    let said: SelfAddressingIdentifier = credential_said
        .parse()
        .map_err(|_| Error::ParseError(format!("invalid credential SAID: {credential_said}")))?;
    issue(id, signer, said).await
}

/// Like [`revoke`], but accepts the credential SAID as a `&str`.
///
/// # Errors
/// - [`Error::ParseError`] if `credential_said` is not a valid SAID.
/// - All errors from [`revoke`].
pub async fn revoke_str<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: S,
    credential_said: &str,
) -> Result<()> {
    let said: SelfAddressingIdentifier = credential_said
        .parse()
        .map_err(|_| Error::ParseError(format!("invalid credential SAID: {credential_said}")))?;
    revoke(id, signer, &said).await
}
