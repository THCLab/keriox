//! Higher-level compound operations for common KERI workflows.
//!
//! These functions combine multiple low-level steps (event generation,
//! signing, witness notification, receipt collection) so callers don't need to
//! orchestrate individual calls. All signing is done internally with the
//! provided signer — callers never touch raw CESR prefix types.
//!
//! When the `keyprovider` feature is enabled, all functions accept
//! `KeriSigner` which can wrap
//! either a legacy `Signer` or any `KeyProvider` implementation.
//! Without the feature, they accept `Arc<Signer>`.
//!
//! For persistence of identifiers across sessions see [`crate::advanced::store`].
//! For signing arbitrary payloads see [`crate::advanced::signing`].

use std::path::PathBuf;

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme, Oobi, SelfSigningPrefix};
use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    event::sections::threshold::SignatureThreshold,
    prefix::{CesrPrimitive, IndexedSignature},
};

use crate::advanced::{
    controller::Controller,
    error::{Error, Result},
    identifier::{Forward, Identifier},
    types::{
        AbandonConfig, DelegationConfig, DelegationRequest, GroupAbandonConfig,
        GroupRotationConfig, IdentifierConfig, MultisigConfig, MultisigRequest, PendingRequest,
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
    /// The CESR self-signing code matching this backend's algorithm.
    ///
    /// Implementations should return the variant whose raw signature byte
    /// layout matches what [`SigningBackend::sign_data`] produces. Used to wrap raw signature
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
impl SigningBackend for crate::advanced::keyprovider_adapter::KeriSigner {
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
        crate::advanced::keyprovider_adapter::signing_code_for(self.algorithm())
    }

    fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        let pk = SigningBackend::public_key(self);
        crate::advanced::keyprovider_adapter::basic_prefix_for(self.algorithm(), pk, transferable)
    }
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Sign `data` with `signer` and wrap the raw bytes in the [`SelfSigningPrefix`]
/// variant matching the signer's algorithm.
pub(crate) fn wrap_sig(signer: &dyn SigningBackend, data: &[u8]) -> Result<SelfSigningPrefix> {
    let bytes = signer.sign_data(data)?;
    Ok(SelfSigningPrefix::new(signer.signing_code(), bytes)?)
}

// ── Public compound operations ────────────────────────────────────────────────

/// Create a new identifier and return it ready to use.
///
/// Performs the full inception flow:
/// 1. Generates an inception event with the given keys and witness config.
/// 2. Signs + finalises it.
/// 3. Notifies witnesses.
/// 4. Collects each witness's receipts.
/// 5. Sends witness OOBIs to watchers and configures each watcher.
///
/// # Errors
/// - [`Error::Controller`] if event generation or finalisation fails.
/// - [`Error::Mechanics`] if witness notification or receipt queries fail.
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
            own_receipts(&mut id, &signer, wit_id).await?;
        }
        id.send_oobi_to_watcher(id.id(), &Oobi::Location(wit.clone()))
            .await?;
        if let IdentifierPrefix::Basic(wit_id) = &wit.eid {
            own_receipts(&mut id, &signer, wit_id).await?;
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

/// Authorize a Messagebox endpoint for an identifier.
///
/// Resolves the messagebox server's OOBI, generates a signed
/// `end_role_add` reply naming it as the identifier's Messagebox endpoint,
/// and delivers the reply to that server so it can serve the end-role to
/// peers resolving this identifier (cross-server mailbox discovery).
///
/// # Errors
/// - [`Error::Mechanics`] if OOBI resolution or the network call fails.
/// - [`Error::Signing`] if signing the reply fails.
pub async fn add_messagebox<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    messagebox_oobi: &LocationScheme,
) -> Result<()> {
    id.resolve_oobi(&Oobi::Location(messagebox_oobi.clone()))
        .await?;
    let rpy = id.add_messagebox(messagebox_oobi.eid.clone())?;
    let sig = wrap_sig(km, rpy.as_bytes())?;
    id.finalize_add_end_role(rpy.as_bytes(), sig).await?;
    Ok(())
}

/// Rotate keys, notify witnesses, and collect their receipts.
///
/// Signs the rotation event with `current_signer`, sends it to witnesses,
/// then collects each witness's receipts.
///
/// # Errors
/// - [`Error::Controller`] if rotation event generation fails.
/// - [`Error::Mechanics`] if witness notification or receipt queries fail.
/// - [`Error::Signing`] if signing fails.
pub async fn rotate<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    current_signer: S,
    config: RotationConfig,
) -> Result<()> {
    let current_keys = vec![committed_key(id, &current_signer)?];
    let new_next_keys = vec![config.new_next_pk];
    let witness_threshold = witness_threshold_or_current(id, config.witness_threshold)?;

    let rotation_event = id
        .rotate(
            current_keys,
            new_next_keys,
            config.new_next_threshold,
            config.witness_to_add,
            config.witness_to_remove,
            witness_threshold,
        )
        .await?;

    let sig = wrap_sig(&current_signer, rotation_event.as_bytes())?;
    id.finalize_rotate(rotation_event.as_bytes(), sig).await?;
    id.notify_witnesses().await?;

    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in witnesses {
        own_receipts(id, &current_signer, &witness).await?;
    }

    Ok(())
}

/// The signer's key in the form the last establishment event committed to.
/// New identifiers commit to the transferable form; identifiers created
/// before keriox did so committed to the non-transferable one, and revealing
/// any other form fails the next-key check.
fn committed_key<S: SigningBackend>(id: &Identifier, signer: &S) -> Result<BasicPrefix> {
    let state = id.find_state(id.id())?;
    let commitments = state.current.next_keys_data.next_keys_hashes();
    [signer.basic_prefix(true), signer.basic_prefix(false)]
        .into_iter()
        .find(|key| {
            commitments
                .iter()
                .any(|digest| digest.verify_binding(key.to_str().as_bytes()))
        })
        .ok_or_else(|| {
            Error::Signing(format!(
                "the signing key is not among {}'s committed next keys",
                id.id()
            ))
        })
}

/// The witness threshold for a new establishment event: `requested` when
/// given, otherwise the threshold the identifier already has, so leaving it
/// out never weakens how many witness receipts later events need.
fn witness_threshold_or_current(id: &Identifier, requested: Option<u64>) -> Result<u64> {
    if let Some(threshold) = requested {
        return Ok(threshold);
    }
    match id.find_state(id.id())?.witness_config.tally {
        SignatureThreshold::Simple(threshold) => Ok(threshold),
        SignatureThreshold::Weighted(_) => Err(Error::Other(
            "weighted witness threshold: give the new witness threshold explicitly".into(),
        )),
    }
}

/// Abandon an identifier, notify witnesses, and collect their receipts.
///
/// `current_signer` holds the key the last establishment event committed
/// to, as for [`rotate`]. The abandoning event reveals it and commits to no
/// next keys, so the identifier's key event log is final: witnesses refuse
/// anything after it and every verifier sees it as abandoned. The revealed
/// key can still sign receipt queries, but nothing it signs speaks for the
/// identifier any more.
///
/// A delegated identifier gets a `drt`, which waits for its delegator to
/// anchor it: this then returns it as [`AwaitingDelegator`], without
/// collecting receipts. Send the delegator [`delegation_request`], take
/// its approval with [`receive_forwards`], and collect the receipts.
///
/// Returns the SAID of the abandoning event.
///
/// # Errors
/// - [`Error::IdentifierAbandoned`] if it already is.
/// - [`Error::Mechanics`] if witness notification or receipt queries fail.
/// - [`Error::Signing`] if signing fails.
pub async fn abandon<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    current_signer: S,
    config: AbandonConfig,
) -> Result<(SelfAddressingIdentifier, Option<AwaitingDelegator>)> {
    let witness_threshold = witness_threshold_or_current(id, config.witness_threshold)?;
    let current_keys = vec![committed_key(id, &current_signer)?];
    let event = id
        .abandon(
            current_keys,
            config.witness_to_add,
            config.witness_to_remove,
            witness_threshold,
            config.anchors,
        )
        .await?;

    let key_event =
        match keri_core::event_message::cesr_adapter::parse_event_type(event.as_bytes()) {
            Ok(keri_core::event_message::cesr_adapter::EventType::KeyEvent(ke)) => ke,
            _ => return Err(Error::EncodingError("abandonment is not a key event".into())),
        };
    let said = key_event
        .digest()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = wrap_sig(&current_signer, event.as_bytes())?;
    id.finalize_rotate(event.as_bytes(), sig.clone()).await?;
    id.notify_witnesses().await?;

    // A delegated identifier's `drt` waits for its delegator. Until then the
    // witnesses know the old keys and would refuse queries signed with the
    // revealed one.
    let state = id.find_state(id.id())?;
    if state.delegator.is_some() {
        return Ok((
            said,
            Some(AwaitingDelegator {
                event: key_event,
                signature: sig,
            }),
        ));
    }
    let witnesses = state.witness_config.witnesses;
    for witness in witnesses {
        own_receipts(id, &current_signer, &witness).await?;
    }

    Ok((said, None))
}

/// A delegated identifier's event waiting for its delegator to anchor it:
/// the event, and the signature it was finalised with.
#[derive(Debug, Clone)]
pub struct AwaitingDelegator {
    pub event: keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
    pub signature: SelfSigningPrefix,
}

/// The delegation request asking `delegator` to anchor `awaiting`: a
/// forward to deliver to it, signed with `signer`, the key of `id` the
/// delegator knows (the one before the event).
///
/// # Errors
/// - [`Error::Signing`] if signing fails.
/// - [`Error::Mechanics`] if the request cannot be built.
pub fn delegation_request<S: SigningBackend>(
    id: &Identifier,
    signer: &S,
    delegator: &IdentifierPrefix,
    awaiting: &AwaitingDelegator,
) -> Result<Forward> {
    use keri_core::{actor::event_generator, exchange::ForwardTopic};
    let exn = event_generator::exchange(id.id(), delegator, &awaiting.event, ForwardTopic::Delegate)
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let exn_signature = id.sign_with_index(wrap_sig(signer, &exn)?, 0)?;
    id.finalize_exchange(
        &exn,
        exn_signature,
        &awaiting.event,
        IndexedSignature::new_both_same(awaiting.signature.clone(), 0),
    )
}

/// Collect the receipts of `about` (the identifier, or a group it is a
/// member of) from `witness_id`: ask the witness for `about`'s key event
/// log, take in the events and receipts it answers with, and pass the
/// identifier's receipts on to the witness.
///
/// A witness that cannot answer yet (it does not hold the log) is no
/// error; ask again later.
///
/// # Errors
/// - [`Error::Mechanics`] on network or processing failures.
/// - [`Error::Signing`] if signing fails.
/// - [`Error::EncodingError`] if query encoding fails.
pub async fn collect_receipts<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    about: &IdentifierPrefix,
    witness_id: &BasicPrefix,
) -> Result<()> {
    let mut queries = vec![];
    for qry in id.query_receipts(about, std::slice::from_ref(witness_id))? {
        let encoded = qry
            .encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let sig = SelfSigningPrefix::new(km.signing_code(), km.sign_data(&encoded)?)?;
        queries.push((qry, sig));
    }
    // A witness's errors (it does not hold the log yet) are no failure:
    // its receipts come with a later call.
    id.finalize_query_receipts(queries).await?;
    Ok(())
}

/// [`collect_receipts`] for the identifier itself.
async fn own_receipts<S: SigningBackend>(
    id: &mut Identifier,
    km: &S,
    witness_id: &BasicPrefix,
) -> Result<()> {
    let own = id.id().clone();
    collect_receipts(id, km, &own, witness_id).await
}

/// Takes forwards delivered to this identifier, or to a group it is a
/// member of (a group event to co-sign, a delegation request, a
/// delegation approval), and returns the requests that need this
/// identifier's decision. The senders' key event logs must be known
/// locally.
///
/// # Errors
/// - [`Error::Controller`] if a forward does not verify.
pub async fn receive_forwards(id: &mut Identifier, stream: &[u8]) -> Result<Vec<PendingRequest>> {
    Ok(id
        .receive_forwards(stream)
        .await?
        .into_iter()
        .filter_map(|action| PendingRequest::try_from(action).ok())
        .collect())
}

// ── Delegation operations ────────────────────────────────────────────────────

/// Approve a pending delegation request (delegator side).
///
/// Signs the delegating IXN event, notifies witnesses, collects their
/// receipts, and returns the approval: the forward to deliver to the
/// delegatee.
///
/// The `request` is typically obtained from [`receive_forwards`].
///
/// # Errors
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
/// - [`Error::EncodingError`] if event encoding fails.
pub async fn approve_delegation<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    request: DelegationRequest,
) -> Result<Forward> {
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

    // Collect the IXN's receipts.
    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &witnesses {
        own_receipts(id, signer, witness).await?;
    }

    // The approval, for the delegatee.
    let sig_exn = wrap_sig(signer, &encoded_exn)?;
    let data_signature = IndexedSignature::new_both_same(sig_ixn, 0);
    let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
    id.finalize_exchange(&encoded_exn, exn_index_sig, &request.delegating_event, data_signature)
}

// ── Multisig operations ──────────────────────────────────────────────────────

/// Request a delegated identifier (delegatee side, step 1 of 2).
///
/// Makes a delegation request for the delegator specified in `config`.
/// The returned identifier is **not** yet accepted — the delegator must
/// approve it first (see [`approve_delegation`]).
///
/// Deliver the returned forwards (the request) to the delegator. Once its
/// approval is delivered back, take it with [`receive_forwards`] and call
/// [`complete_delegation`].
///
/// Returns `(identifier_handle, delegated_prefix, forwards)`.
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
) -> Result<(Identifier, IdentifierPrefix, Vec<Forward>)> {
    let controller = Controller::new(db_path)?;
    request_delegation_with_controller(&controller, signer, next_pk, config).await
}

/// Like [`request_delegation`] but reuses an existing [`Controller`] instead
/// of opening a fresh one — required when the database is already open (a
/// store's cached controller, or a shared-layout store where every alias
/// uses one database).
pub async fn request_delegation_with_controller<S: SigningBackend + Clone + 'static>(
    controller: &Controller,
    signer: S,
    next_pk: BasicPrefix,
    config: DelegationConfig,
) -> Result<(Identifier, IdentifierPrefix, Vec<Forward>)> {
    // Create a temporary identifier (needed by incept_group).
    let temp_config = IdentifierConfig {
        witnesses: config.witnesses.clone(),
        witness_threshold: config.witness_threshold,
        watchers: vec![], // watchers configured after delegation is accepted
        algorithm: config.algorithm,
    };
    let mut temp_id =
        create_identifier_with_controller(controller, signer.clone(), next_pk, temp_config)
            .await?;

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

    let (delegated_prefix, forwards) = temp_id
        .finalize_group_incept(
            dip.as_bytes(),
            sig_icp,
            vec![(delegation_exn.as_bytes().to_vec(), exn_index_sig)],
        )
        .await?;

    Ok((temp_id, delegated_prefix, forwards))
}

/// Complete the delegation after the delegator has approved (delegatee
/// side, step 2 of 2).
///
/// Takes the approval forward delivered from the delegator (its delegating
/// event), which lets the delegated inception go to the witnesses, and
/// collects their receipts so the delegated identifier is accepted.
///
/// # Preconditions
/// The delegator's key event log must be known locally (e.g. via
/// `identifier.resolve_oobi(&delegator_oobi)`).
///
/// # Errors
/// - [`Error::DelegatorKelNotAvailable`] if the delegator's events are
///   not in the local database. Resolve the delegator's OOBI first.
/// - [`Error::NoWitnesses`] if the identifier has no witnesses configured.
/// - [`Error::Controller`] if the approval does not verify.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn complete_delegation<S: SigningBackend + Clone + 'static>(
    temp_id: &mut Identifier,
    signer: &S,
    delegated_prefix: &IdentifierPrefix,
    delegator_id: &IdentifierPrefix,
    approval: &[u8],
) -> Result<()> {
    let witnesses: Vec<BasicPrefix> = temp_id.witnesses();
    if witnesses.is_empty() {
        return Err(Error::NoWitnesses(temp_id.id().clone()));
    }
    if temp_id.get_kel(delegator_id).is_none() {
        return Err(Error::DelegatorKelNotAvailable(delegator_id.clone()));
    }
    temp_id.receive_forwards(approval).await?;
    for witness in &witnesses {
        collect_receipts(temp_id, signer, delegated_prefix, witness).await?;
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
/// a forward.
///
/// After the delegator returns the signed delegating `ixn`, call
/// [`finalize_delegation_with_seal`] on the returned identifier.
pub async fn build_delegation_request<S: SigningBackend + Clone + 'static>(
    db_path: PathBuf,
    signer: S,
    next_pk: BasicPrefix,
    config: DelegationConfig,
) -> Result<(Identifier, IdentifierPrefix, String)> {
    let controller = Controller::new(db_path)?;
    build_delegation_request_with_controller(&controller, signer, next_pk, config).await
}

/// Like [`build_delegation_request`] but reuses an existing
/// [`Controller`] instead of opening a fresh one on the db path.
///
/// redb permits only one open `Database` per file in a process. A
/// caller that also accesses the alias through a cached controller
/// (e.g. `KeriStore::get_or_create_controller`, used by `load`,
/// signing and `finalize_delegation_with_seal`) must mint the delegated
/// AID through that same controller — otherwise the two opens collide
/// with "Database already open. Cannot acquire lock." Pass the cached
/// controller here so the whole delegation lifecycle (mint → finalize →
/// publish) shares one handle.
pub async fn build_delegation_request_with_controller<S: SigningBackend + Clone + 'static>(
    controller: &Controller,
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
    let mut temp_id =
        create_identifier_with_controller(controller, signer.clone(), next_pk, temp_config)
            .await?;

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

    // The request travels as the signed `dip` itself, out of band.
    let (delegated_prefix, _forwards) = temp_id
        .finalize_group_incept(
            dip.as_bytes(),
            sig_icp,
            vec![(delegation_exn.as_bytes().to_vec(), exn_index_sig)],
        )
        .await?;

    // Return the *signed* `dip` (event + signature couples), not the
    // bare event. The delegated inception is escrowed locally until the
    // delegator anchors it, so the finalized-KEL accessors only expose
    // the unsigned form — and a sponsor that imports that to build the
    // anchoring `ixn` rejects it with "Missing controller signatures
    // attachment", leaving the delegation unanchored and the delegatee's
    // KEL unservable to watchers. For an inception the prefix is the
    // event's SAID, so we look the stored signed event up by that
    // digest. Fall back to the unsigned event if (unexpectedly) the
    // store can't produce it.
    let signed_dip = match &delegated_prefix {
        IdentifierPrefix::SelfAddressing(said) => temp_id
            .get_signed_event_cesr(&said.said)
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or(dip),
        _ => dip,
    };

    Ok((temp_id, delegated_prefix, signed_dip))
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
/// Does NOT call [`Identifier::notify_witnesses`] — the caller is
/// responsible for transport: of the signed `ixn` to the delegatee, and of
/// the returned forwards to the other group members.
pub async fn build_delegation_approval<S: SigningBackend + Clone + 'static>(
    delegator_id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    delegated_dip_cesr: &str,
    participants: &[IdentifierPrefix],
) -> Result<(String, Vec<Forward>)> {
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

    let forwards = delegator_id
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
    let encoded = String::from_utf8(encoded).map_err(|e| Error::EncodingError(e.to_string()))?;
    Ok((encoded, forwards))
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
/// caller-identifier's witnesses and then collect each witness's
/// receipts. Wraps the witness legs of
/// [`approve_delegation`] so other callers (notably the cosigned
/// delegation flow) can reuse them without duplicating the loop.
pub async fn publish_event_and_collect_receipts<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
) -> Result<()> {
    id.notify_witnesses().await?;
    let witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &witnesses {
        own_receipts(id, signer, witness).await?;
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
/// Notifies witnesses and collects receipts; returns the forwards to
/// deliver to the other members.
pub async fn anchor_group<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    anchors: &[SelfAddressingIdentifier],
    participants: &[IdentifierPrefix],
) -> Result<Vec<Forward>> {
    let (ixn_cesr, exn_messages) = id.anchor_group(group_id, anchors, participants)?;

    let sig_ixn = wrap_sig(signer, ixn_cesr.as_bytes())?;

    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    let forwards = id
        .finalize_group_event(ixn_cesr.as_bytes(), sig_ixn, exchange_pairs)
        .await?;
    id.notify_witnesses().await?;

    let caller_witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &caller_witnesses {
        own_receipts(id, signer, witness).await?;
    }
    let group_witnesses = id.find_state(group_id)?.witness_config.witnesses;
    for witness in &group_witnesses {
        collect_receipts(id, signer, group_id, witness).await?;
    }

    Ok(forwards)
}

/// Out-of-band variant of [`anchor_group`]: build the `ixn` event,
/// sign it locally, and return the event + per-co-signer exchange
/// messages as CESR strings for transport. Co-signers reconstruct a
/// [`MultisigRequest`] via [`MultisigRequest::from_cesr`] and call
/// [`accept_multisig`].
///
/// Does NOT call [`Identifier::notify_witnesses`]. The caller's signature
/// is still applied locally.
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

    // The exchange messages returned travel out of band instead.
    let _forwards = id
        .finalize_group_event(ixn_cesr.as_bytes(), sig_ixn, exchange_pairs)
        .await?;

    Ok((ixn_cesr, exn_messages))
}

/// Create a multisig identifier (initiator side).
///
/// Generates the group inception event, signs it, and returns the
/// invitations to deliver to the other members. The identifier is **not**
/// yet accepted — other members must co-sign via [`accept_multisig`], and
/// all members must call [`sync_multisig`] to finalise.
///
/// Returns the multisig `IdentifierPrefix` and the invitations.
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
) -> Result<(IdentifierPrefix, Vec<Forward>)> {
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

    id.finalize_group_incept(icp.as_bytes(), sig_icp, exchange_pairs)
        .await
}

/// Rotate the keys of an established multisig (group) identifier.
///
/// Builds a `rot` event against `group_id`, signs it with the caller's
/// `signer`, signs an exchange message for every other remaining member,
/// finalises the local state, collects the caller's and the group's
/// receipts, and returns the forwards to deliver to the other members.
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
) -> Result<Vec<Forward>> {
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

    let forwards = id
        .finalize_group_event(rot_event.as_bytes(), sig_rot, exchange_pairs)
        .await?;
    id.notify_witnesses().await?;

    let caller_witnesses = id.find_state(id.id())?.witness_config.witnesses;
    for witness in &caller_witnesses {
        own_receipts(id, signer, witness).await?;
    }
    let group_witnesses = id.find_state(group_id)?.witness_config.witnesses;
    for witness in &group_witnesses {
        collect_receipts(id, signer, group_id, witness).await?;
    }

    Ok(forwards)
}

/// Abandon a multisig group identifier, or a delegated identifier through
/// its delegate's member identifier (initiator side).
///
/// Like [`rotate_group`], each member first rotates its own identifier so
/// its current key is the one the group committed to; `signer` holds the
/// caller's. The event commits to no next keys. Other members co-sign with
/// [`accept_multisig`]. For a delegated identifier the delegator receives a
/// delegation request and anchors the `drt` like the delegated inception
/// (or through [`build_delegation_approval`] out of band).
///
/// # Errors
/// - [`Error::IdentifierAbandoned`] if the group or a member is abandoned.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn abandon_group<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    group_id: &IdentifierPrefix,
    config: GroupAbandonConfig,
) -> Result<Vec<Forward>> {
    let (event, exn_messages) = id
        .abandon_group(
            group_id,
            config.participants,
            config.signature_threshold,
            config.anchors,
        )
        .await?;

    let sig = wrap_sig(signer, event.as_bytes())?;
    let mut exchange_pairs = Vec::with_capacity(exn_messages.len());
    for exn in &exn_messages {
        let sig_exn = wrap_sig(signer, exn.as_bytes())?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        exchange_pairs.push((exn.as_bytes().to_vec(), exn_index_sig));
    }

    let forwards = id
        .finalize_group_event(event.as_bytes(), sig, exchange_pairs)
        .await?;
    id.notify_witnesses().await?;

    let group_witnesses = id.find_state(group_id)?.witness_config.witnesses;
    for witness in &group_witnesses {
        collect_receipts(id, signer, group_id, witness).await?;
    }

    Ok(forwards)
}

/// Accept a pending group event delivered to this member (joiner side).
///
/// Handles both group inceptions and group rotations: the underlying
/// `finalize_group_event` is event-type agnostic and the index-discovery
/// helper dispatches on event-data variant.
///
/// Co-signs the event and returns the forwards that carry the signature to
/// the other members. The `request` is obtained from [`receive_forwards`]
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
) -> Result<Vec<Forward>> {
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
    .await
}

/// Synchronise the multisig identifier state: collect the group's
/// receipts from its witnesses. Co-signatures from other members arrive as
/// forwards ([`receive_forwards`]). Call it after enough co-signatures
/// have been delivered.
///
/// After this call, verify acceptance with
/// `id.find_state(multisig_id)`.
///
/// # Errors
/// - [`Error::NoWitnesses`] if neither the group nor the identifier has
///   witnesses configured.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn sync_multisig<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    multisig_id: &IdentifierPrefix,
) -> Result<()> {
    // A group not accepted yet has no state: its witnesses are then taken
    // to be the member's, as the group's inception names them.
    let witnesses: Vec<BasicPrefix> = id
        .find_state(multisig_id)
        .map(|state| state.witness_config.witnesses)
        .unwrap_or_else(|_| id.witnesses());
    if witnesses.is_empty() {
        return Err(Error::NoWitnesses(id.id().clone()));
    }
    for witness in &witnesses {
        collect_receipts(id, signer, multisig_id, witness).await?;
    }
    Ok(())
}

/// Co-sign a pending group event delivered as persisted JSON (joiner side).
///
/// JSON-string counterpart of [`accept_multisig`] for callers that persist
/// pending requests via [`MultisigRequest::event_json`] /
/// [`MultisigRequest::exchange_json`]. Signs the event, signs every exchange
/// message at key index 0, then dispatches on the event type: group (or
/// delegated) inceptions are finalised with `finalize_group_incept` and
/// return `Some(group_prefix)`; all other group events (rotations, anchors)
/// are finalised with `finalize_group_event` and return `None`. The
/// forwards returned carry the signature to the other members.
///
/// # Errors
/// - [`Error::EncodingError`] if the JSON or event encoding is invalid.
/// - [`Error::Mechanics`] on network failures.
/// - [`Error::Signing`] if signing fails.
pub async fn accept_multisig_event<S: SigningBackend + Clone + 'static>(
    id: &mut Identifier,
    signer: &S,
    event_json: &str,
    exchange_jsons: &[String],
) -> Result<(Option<IdentifierPrefix>, Vec<Forward>)> {
    use keri_core::event_message::EventTypeTag;

    let event: keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent> =
        serde_json::from_str(event_json)
            .map_err(|e| Error::EncodingError(format!("event JSON: {e}")))?;
    let encoded_event = event
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig_event = wrap_sig(signer, &encoded_event)?;

    let mut signed_exchanges = Vec::with_capacity(exchange_jsons.len());
    for exn_json in exchange_jsons {
        let exn: keri_core::exchange::ExchangeMessage = serde_json::from_str(exn_json)
            .map_err(|e| Error::EncodingError(format!("exchange JSON: {e}")))?;
        let encoded_exn = exn
            .encode()
            .map_err(|e| Error::EncodingError(e.to_string()))?;
        let sig_exn = wrap_sig(signer, &encoded_exn)?;
        let exn_index_sig = id.sign_with_index(sig_exn, 0)?;
        signed_exchanges.push((encoded_exn, exn_index_sig));
    }

    match event.event_type {
        EventTypeTag::Icp | EventTypeTag::Dip => {
            let (group_prefix, forwards) = id
                .finalize_group_incept(&encoded_event, sig_event, signed_exchanges)
                .await?;
            Ok((Some(group_prefix), forwards))
        }
        _ => {
            let forwards = id
                .finalize_group_event(&encoded_event, sig_event, signed_exchanges)
                .await?;
            Ok((None, forwards))
        }
    }
}

/// Build the forward exchange for a group event and the caller's signatures
/// over both, then finalise the group event locally.
pub(crate) async fn finalize_group_anchor<S: SigningBackend + Clone + 'static>(
    group: &mut Identifier,
    member: &IdentifierPrefix,
    signer: &S,
    ixn: &keri_core::event_message::msg::KeriEvent<keri_core::event::KeyEvent>,
) -> Result<Vec<Forward>> {
    use keri_core::actor::event_generator;
    use keri_core::event_message::signature::{Signature, SignerData};
    use keri_core::exchange::ForwardTopic;

    let exn = event_generator::exchange(
        member,
        group.id(),
        ixn,
        ForwardTopic::Multisig,
    )
    .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let encoded_ixn = ixn
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;

    let sig_ixn = wrap_sig(signer, &encoded_ixn)?;
    let sig_exn = wrap_sig(signer, &exn)?;

    // Anchor the exchange signature to the member's establishment event seal:
    // the exchange wire format only transports seal-anchored transferable
    // signatures.
    let member_seal = group
        .last_establishment_event_seal_of(member)
        .ok_or_else(|| Error::IdentifierNotFound(member.clone()))?;
    let exn_index_sig = Signature::Transferable(
        SignerData::EventSeal(member_seal),
        vec![IndexedSignature::new_both_same(sig_exn, 0)],
    );

    group
        .finalize_group_event(&encoded_ixn, sig_ixn, vec![(exn, exn_index_sig)])
        .await
}
