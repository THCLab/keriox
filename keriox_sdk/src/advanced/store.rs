//! Persistent storage for named KERI identifiers.
//!
//! [`KeriStore`] manages a root directory that holds one sub-directory per
//! *alias* (a human-readable name for an identifier). Each alias directory
//! stores the Redb database, the current and next signing-key seeds, the
//! identifier prefix, and an optional registry prefix.
//!
//! The on-disk layout is identical to the one used by `dkms-bin`, so existing
//! databases can be opened without migration.
//!
//! See [`crate::advanced::operations`] for the functions that use the identifiers
//! returned by this module.
//!
//! # Disk layout
//!
//! ```text
//! <root>/
//!   <alias>/
//!     db/           ← Redb database directory
//!     priv_key      ← current SeedPrefix (KERI canonical text)
//!     next_priv_key ← next SeedPrefix (KERI canonical text)
//!     id            ← IdentifierPrefix (KERI canonical text)
//!     reg_id        ← IdentifierPrefix (optional, set after incept_registry)
//! ```

use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, Mutex},
};

use keri_controller::{controller::RedbIdentifier, IdentifierPrefix};
use keri_core::{prefix::SeedPrefix, signer::Signer};

use crate::{
    controller::Controller,
    error::{Error, Result},
    identifier::Identifier,
    operations::{
        create_identifier_with_controller, create_multisig, request_delegation, rotate_group,
    },
    types::{DelegationConfig, GroupRotationConfig, IdentifierConfig, MultisigConfig},
};

/// Manages a directory of named KERI identifiers.
///
/// Each identifier is stored under `<root>/<alias>/` using the standard
/// disk layout. Use [`KeriStore::open`] to create or open a store, then
/// [`KeriStore::create`] to provision new identifiers and [`KeriStore::load`]
/// to restore them across sessions.
pub struct KeriStore {
    root: PathBuf,
    controllers: Mutex<HashMap<PathBuf, Arc<Controller>>>,
}

impl KeriStore {
    /// Open (or create) a store rooted at `root`.
    ///
    /// Creates the root directory if it does not exist.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the directory cannot be created.
    pub fn open(root: PathBuf) -> Result<Self> {
        std::fs::create_dir_all(&root)
            .map_err(|e| Error::PersistenceError(format!("cannot create store root: {e}")))?;
        Ok(Self {
            root,
            controllers: Mutex::new(HashMap::new()),
        })
    }

    /// Create a brand-new identifier, persist all state, and return the live
    /// handle together with the current signer.
    ///
    /// Generates random key pairs for the current and next keys internally,
    /// using `config.algorithm` (default: Ed25519). `config` also controls
    /// witnesses and watchers.
    ///
    /// To make a P-256 AID controlled by a mobile platform key, pass
    /// [`IdentifierConfig::p256()`]; to make a secp256k1 AID, pass
    /// [`IdentifierConfig::secp256k1()`].
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - [`Error::Signing`] if seed generation fails.
    /// - Propagates errors from [`create_identifier`].
    pub async fn create(
        &self,
        alias: &str,
        config: IdentifierConfig,
    ) -> Result<(Identifier, Arc<Signer>)> {
        let current_seed = crate::advanced::keys::generate_seed(config.algorithm)?;
        let next_seed = crate::advanced::keys::generate_seed(config.algorithm)?;

        self.create_with_seeds(alias, current_seed, next_seed, config)
            .await
    }

    /// Create a brand-new identifier with caller-provided seeds.
    ///
    /// Useful for deterministic key derivation (e.g. from a mnemonic). The
    /// seeds are persisted to disk and the identifier is fully incepted before
    /// returning.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - [`Error::Signing`] if the seed cannot produce a key pair.
    /// - Propagates errors from [`create_identifier`].
    pub async fn create_with_seeds(
        &self,
        alias: &str,
        current_seed: SeedPrefix,
        next_seed: SeedPrefix,
        config: IdentifierConfig,
    ) -> Result<(Identifier, Arc<Signer>)> {
        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;

        let db_path = alias_dir.join("db");

        let signer = Arc::new(
            Signer::new_with_seed(&current_seed).map_err(|e| Error::Signing(e.to_string()))?,
        );

        // Derive the next-key commitment in the BasicPrefix variant matching
        // the next seed's algorithm (Ed25519 / secp256k1 / P-256). The NT
        // (non-transferable) flavor is the canonical choice for next-key
        // commitments.
        let next_pk = crate::advanced::keys::derive_public_key(&next_seed, false)?;

        let controller = self.get_or_create_controller(db_path)?;
        let id = create_identifier_with_controller(&controller, signer.clone(), next_pk, config)
            .await?;

        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "priv_key", &current_seed.to_str())?;
        self.write_file(alias, "next_priv_key", &next_seed.to_str())?;
        self.write_file(alias, "id", &id.id().to_str())?;

        Ok((id, signer))
    }

    /// Load an existing identifier from disk.
    ///
    /// Reconstructs the `Identifier` by opening the Redb database and reading
    /// the persisted identifier prefix. The signing key is **not** loaded here
    /// — use [`KeriStore::load_signer`] for that.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the alias directory or files are missing.
    /// - [`Error::IdentifierNotFound`] if the `id` file cannot be parsed.
    /// - [`Error::Controller`] if the database cannot be opened.
    pub fn load(&self, alias: &str) -> Result<Identifier> {
        let alias_dir = self.alias_dir(alias);
        let db_path = alias_dir.join("db");

        let id_str = self.read_file(alias, "id")?;
        let id_prefix = IdentifierPrefix::from_str(id_str.trim()).map_err(|_| {
            Error::IdentifierNotFound(IdentifierPrefix::SelfAddressing(Default::default()))
        })?;

        let reg_id = self
            .read_file(alias, "reg_id")
            .ok()
            .and_then(|s| IdentifierPrefix::from_str(s.trim()).ok());

        let controller = self.get_or_create_controller(db_path)?;

        let inner = RedbIdentifier::new(
            id_prefix,
            reg_id,
            controller.inner.known_events.clone(),
            controller.inner.communication.clone(),
            controller.inner.cache.clone(),
        );

        Ok(Identifier { inner })
    }

    /// Load the current signing key for an alias.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `priv_key` file is missing or invalid.
    /// - [`Error::Signing`] if the seed cannot produce a signer.
    pub fn load_signer(&self, alias: &str) -> Result<Arc<Signer>> {
        let seed = self.load_seed(alias, "priv_key")?;
        let signer = Signer::new_with_seed(&seed).map_err(|e| Error::Signing(e.to_string()))?;
        Ok(Arc::new(signer))
    }

    /// Load the next signing key (used as the current key after rotation).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `next_priv_key` file is missing or invalid.
    /// - [`Error::Signing`] if the seed cannot produce a signer.
    pub fn load_next_signer(&self, alias: &str) -> Result<Arc<Signer>> {
        let seed = self.load_seed(alias, "next_priv_key")?;
        let signer = Signer::new_with_seed(&seed).map_err(|e| Error::Signing(e.to_string()))?;
        Ok(Arc::new(signer))
    }

    /// Commit a rotation: promote `next_priv_key` → `priv_key`, persist a new
    /// next seed, and save the updated identifier prefix.
    ///
    /// Call this after [`crate::advanced::operations::rotate`] has succeeded.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_rotation(&self, alias: &str, new_next_seed: SeedPrefix) -> Result<()> {
        // Promote: next becomes current.
        let next_content = self.read_file(alias, "next_priv_key")?;
        self.write_file(alias, "priv_key", &next_content)?;

        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "next_priv_key", &new_next_seed.to_str())?;

        Ok(())
    }

    /// Rotate keys for an identifier: generate a new next key pair, perform
    /// the rotation via [`crate::advanced::operations::rotate`], and persist the updated
    /// seeds.
    ///
    /// This is a high-level convenience that wraps the full rotation lifecycle.
    /// For external key providers (Android Keystore, HSMs), use
    /// [`crate::advanced::operations::rotate`] directly with your `SigningBackend`.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - [`Error::Signing`] if key generation or signing fails.
    /// - Propagates errors from [`crate::advanced::operations::rotate`].
    pub async fn rotate(&self, alias: &str) -> Result<()> {
        // KERI rotation reveals the previously pre-committed next-key.
        // The event's controlling keys are the next-signer's keys (now
        // becoming current), and the signature must come from that same
        // signer (since they own the key being revealed).
        let next_seed = self.load_seed(alias, "next_priv_key")?;
        let algorithm = crate::advanced::keys::seed_algorithm(&next_seed)?;
        // The new next-key matches the curve of the key becoming current,
        // so the AID stays on a single curve across rotations (otherwise
        // a P-256 AID would silently transition to Ed25519 after the
        // rotation after next).
        let (new_next_seed, new_next_pk) = crate::advanced::keys::generate_keypair(algorithm, false)?;

        let mut id = self.load(alias)?;
        let signer = self.load_next_signer(alias)?;

        let config = crate::advanced::types::RotationConfig {
            new_next_pk,
            new_next_threshold: 1,
            witness_to_add: vec![],
            witness_to_remove: vec![],
            witness_threshold: 0,
        };
        crate::advanced::operations::rotate(&mut id, signer, config).await?;

        self.save_rotation(alias, new_next_seed)?;
        Ok(())
    }

    /// Rotate keys with explicit witness changes and seed control.
    ///
    /// Like [`KeriStore::rotate`], but driven by a
    /// [`StoreRotationConfig`](crate::advanced::types::StoreRotationConfig): witnesses
    /// can be added/removed, thresholds adjusted, and the new next seed
    /// supplied instead of generated.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - [`Error::Signing`] if key generation or signing fails.
    /// - Propagates errors from [`crate::advanced::operations::rotate`].
    pub async fn rotate_with(
        &self,
        alias: &str,
        config: crate::advanced::types::StoreRotationConfig,
    ) -> Result<()> {
        let next_seed = self.load_seed(alias, "next_priv_key")?;
        let new_next_seed = match config.new_next_seed {
            Some(seed) => seed,
            None => {
                let algorithm = crate::advanced::keys::seed_algorithm(&next_seed)?;
                crate::advanced::keys::generate_seed(algorithm)?
            }
        };
        let new_next_pk = crate::advanced::keys::derive_public_key(&new_next_seed, false)?;

        let mut id = self.load(alias)?;
        let signer = self.load_next_signer(alias)?;

        let rotation = crate::advanced::types::RotationConfig {
            new_next_pk,
            new_next_threshold: config.new_next_threshold,
            witness_to_add: config.witness_to_add,
            witness_to_remove: config.witness_to_remove,
            witness_threshold: config.witness_threshold,
        };
        crate::advanced::operations::rotate(&mut id, signer, rotation).await?;

        self.save_rotation(alias, new_next_seed)?;
        Ok(())
    }

    /// Read the current signing seed for an alias (e.g. for identifier export).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `priv_key` file is missing or invalid.
    pub fn current_seed(&self, alias: &str) -> Result<SeedPrefix> {
        self.load_seed(alias, "priv_key")
    }

    /// Read the next (pre-rotated) signing seed for an alias.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `next_priv_key` file is missing or invalid.
    pub fn next_seed(&self, alias: &str) -> Result<SeedPrefix> {
        self.load_seed(alias, "next_priv_key")
    }

    /// Persist both signing seeds for an alias (e.g. for identifier import).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_seeds(&self, alias: &str, current: &SeedPrefix, next: &SeedPrefix) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;
        self.write_file(alias, "priv_key", &current.to_str())?;
        self.write_file(alias, "next_priv_key", &next.to_str())
    }

    /// Persist a registry identifier after [`crate::advanced::operations::incept_registry`].
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_registry(&self, alias: &str, registry_id: &IdentifierPrefix) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "reg_id", &registry_id.to_str())
    }

    /// Persist the identifier prefix for an alias.
    ///
    /// Used when creating identifiers through the operations layer directly
    /// (bypassing [`KeriStore::create`]).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_id(&self, alias: &str, id: &IdentifierPrefix) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "id", &id.to_str())
    }

    /// Create a delegated identifier (delegatee side).
    ///
    /// Generates random Ed25519 key pairs, creates a temporary identifier,
    /// sends a delegation request to the delegator via witnesses, and
    /// persists all state. The delegated identifier is **not** yet accepted
    /// — the delegator must approve it first.
    ///
    /// After approval, call [`crate::advanced::operations::complete_delegation`] with
    /// the returned `Identifier` to complete the process.
    ///
    /// Returns `(temporary_identifier, delegated_prefix, current_signer)`.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - Propagates errors from [`request_delegation`].
    pub async fn create_delegated(
        &self,
        alias: &str,
        config: DelegationConfig,
    ) -> Result<(Identifier, IdentifierPrefix, Arc<Signer>)> {
        let current_seed = crate::advanced::keys::generate_seed(config.algorithm)?;
        let next_seed = crate::advanced::keys::generate_seed(config.algorithm)?;

        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;

        let db_path = alias_dir.join("db");

        let signer = Arc::new(
            Signer::new_with_seed(&current_seed).map_err(|e| Error::Signing(e.to_string()))?,
        );

        let next_pk = crate::advanced::keys::derive_public_key(&next_seed, false)?;

        let delegator_id = config.delegator.clone();
        let (temp_id, delegated_prefix) =
            request_delegation(db_path, signer.clone(), next_pk, config).await?;

        // Persist seeds, temporary identifier, delegated prefix, and delegator.
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "priv_key", &current_seed.to_str())?;
        self.write_file(alias, "next_priv_key", &next_seed.to_str())?;
        self.write_file(alias, "id", &temp_id.id().to_str())?;
        self.write_file(alias, "delegated_id", &delegated_prefix.to_str())?;
        self.write_file(alias, "delegator_id", &delegator_id.to_str())?;

        Ok((temp_id, delegated_prefix, signer))
    }

    /// Persist the delegator identifier for an alias.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_delegator(&self, alias: &str, delegator_id: &IdentifierPrefix) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "delegator_id", &delegator_id.to_str())
    }

    /// Persist the delegated identifier prefix for an alias.
    ///
    /// The counterpart of [`load_delegated_prefix`](Self::load_delegated_prefix).
    /// Callers that mint a delegated AID outside [`create_delegated`](Self::create_delegated)
    /// (e.g. the cached-controller delegation path) must record this so the
    /// alias can later be resolved to its *delegated* AID rather than the
    /// throwaway precursor `id` — without it the delegatee operates on the
    /// precursor and can't publish or serve its own delegated KEL.
    pub fn save_delegated_prefix(
        &self,
        alias: &str,
        delegated_id: &IdentifierPrefix,
    ) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "delegated_id", &delegated_id.to_str())
    }

    /// Load the delegated identifier prefix for an alias.
    ///
    /// Returns an error if this alias is not a delegated identifier.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `delegated_id` file is missing or invalid.
    pub fn load_delegated_prefix(&self, alias: &str) -> Result<IdentifierPrefix> {
        let s = self.read_file(alias, "delegated_id")?;
        IdentifierPrefix::from_str(s.trim())
            .map_err(|_| Error::PersistenceError("invalid delegated_id".into()))
    }

    /// Load the delegator identifier prefix for an alias.
    ///
    /// Returns an error if this alias is not a delegated identifier.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `delegator_id` file is missing or invalid.
    pub fn load_delegator(&self, alias: &str) -> Result<IdentifierPrefix> {
        let s = self.read_file(alias, "delegator_id")?;
        IdentifierPrefix::from_str(s.trim())
            .map_err(|_| Error::PersistenceError("invalid delegator_id".into()))
    }

    // ── Multisig group methods (preferred names) ──────────────────────────────

    /// Create a multisig group identifier and persist metadata (initiator side).
    ///
    /// The caller's individual identifier must already exist under
    /// `member_alias`. This method creates a new alias directory for the
    /// group that stores the group prefix, member list, and a back-reference
    /// to the member alias.
    ///
    /// Other participants must still co-sign via
    /// [`crate::advanced::operations::accept_multisig`], and all participants must call
    /// [`crate::advanced::operations::sync_multisig`] to finalise.
    ///
    /// Returns the group `IdentifierPrefix`.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - Propagates errors from [`create_multisig`].
    pub async fn create_multisig_group(
        &self,
        group_alias: &str,
        member_alias: &str,
        config: MultisigConfig,
    ) -> Result<IdentifierPrefix> {
        let mut id = self.load(member_alias)?;
        let signer = self.load_signer(member_alias)?;

        let members = config.members.clone();
        let group_prefix = create_multisig(&mut id, &signer, config).await?;

        self.persist_group_metadata(group_alias, &group_prefix, &members, member_alias)?;

        Ok(group_prefix)
    }

    /// Rotate an established multisig group identifier.
    ///
    /// Looks up the caller's signer and the group prefix from local
    /// storage by `group_alias`, calls [`crate::advanced::operations::rotate_group`],
    /// and rewrites the `participants` file with the post-rotation set on
    /// success. The caller does not have to handle signing, exchange
    /// messages, mailbox queries, or KERI event types directly.
    ///
    /// **Precondition:** the caller's individual KEL for `member_alias`
    /// must already be rotated locally so that the member's *current*
    /// individual public key matches the group's prior next-key
    /// commitment for that member. The convenience flow is:
    ///
    /// ```ignore
    /// store.rotate(member_alias).await?;            // local rotation
    /// store.rotate_multisig_group(group_alias, …).await?;  // group rotation
    /// ```
    ///
    /// Failing to pre-rotate yields
    /// `Mechanics(EventProcessingError(SignatureVerificationError))`
    /// because the contribution is signed with a key the group has not
    /// yet committed to.
    ///
    /// When the prior signature threshold is greater than 1, this call
    /// submits the caller's signature; remaining co-signers complete the
    /// rotation by calling [`crate::advanced::operations::accept_multisig`] on the
    /// pending request, after which every member calls
    /// [`crate::advanced::operations::sync_multisig`].
    ///
    /// On partial failure the persisted member set is **not** updated, so
    /// retrying will rebuild a fresh rotation event against the
    /// already-applied local state. Callers that retry should reload the
    /// identifier from the store first.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - Propagates errors from [`crate::advanced::operations::rotate_group`].
    pub async fn rotate_multisig_group(
        &self,
        group_alias: &str,
        config: GroupRotationConfig,
    ) -> Result<()> {
        let member_alias = self.load_multisig_member_alias(group_alias)?;
        let group_id = self.load_multisig_prefix(group_alias)?;

        let mut id = self.load(&member_alias)?;
        // Multisig rotation requires the caller to have already locally
        // rotated their individual KEL (so their CURRENT individual key
        // matches the group's prior next-key commitment for this member).
        // Sign with the current signer.
        let signer = self.load_signer(&member_alias)?;

        let new_members = config.new_participants.clone();
        rotate_group(&mut id, &signer, &group_id, config).await?;

        self.persist_group_metadata(group_alias, &group_id, &new_members, &member_alias)?;
        Ok(())
    }

    /// Register a local alias that "views" an externally-incepted
    /// AID — the alias's `id` file is set to `identity_prefix` (so
    /// [`KeriStore::load`] returns an [`Identifier`] bound to that
    /// AID), and its `priv_key` file holds a signing seed (so
    /// [`KeriStore::load_signer`] yields a [`Signer`] for the
    /// member-slot pubkey participating in `identity_prefix`'s
    /// multi-sig key set).
    ///
    /// No icp event is generated for the alias — the AID it views
    /// already exists elsewhere (typically incepted by another
    /// device). After this call the alias's redb is initialised
    /// empty; callers usually follow up with
    /// `import_kel_tofu` (cyfron-core) to ingest the AID's KEL
    /// before reading state.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn register_group_view(
        &self,
        alias: &str,
        identity_prefix: &IdentifierPrefix,
        slot_seed: SeedPrefix,
    ) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        // Touch the alias dir + db path so subsequent
        // `KeriStore::load` opens the redb cleanly.
        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;
        let db_path = alias_dir.join("db");
        let _controller = self.get_or_create_controller(db_path)?;
        self.write_file(alias, "id", &identity_prefix.to_str())?;
        self.write_file(alias, "priv_key", &slot_seed.to_str())?;
        Ok(())
    }

    /// Persist a single signing seed under `alias` without
    /// performing an inception event.
    ///
    /// `create` and `create_with_seeds` both end with a `KeyEvent::Icp`
    /// pushed onto the alias's KEL, which is the right thing when the
    /// alias represents a brand-new identifier. Multi-sig group
    /// members are different: the group AID was incepted (or
    /// rotated-into) elsewhere, and this alias just needs to hold
    /// the slot signing key that participates in the group's
    /// current key set. No KEL of its own — calls to
    /// [`KeriStore::load_signer`] will succeed because the
    /// `priv_key` file is present, but [`KeriStore::load`] will
    /// fail because there is no `id` file (which is correct: the
    /// alias does not own an AID, it backs a member slot of a
    /// group AID tracked under a different alias).
    ///
    /// Pair with [`KeriStore::save_multisig`] on the group alias to
    /// stitch the group → member-alias back-reference.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn import_member_seed(&self, alias: &str, seed: SeedPrefix) -> Result<()> {
        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "priv_key", &seed.to_str())
    }

    /// Persist multisig group metadata after joining (joiner side).
    ///
    /// Call this after [`crate::advanced::operations::accept_multisig`] to record the
    /// group prefix, member list, and member alias for later retrieval.
    /// Also use it on the joiner side after a co-signed rotation to
    /// refresh the persisted `participants` list.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    pub fn save_multisig(
        &self,
        group_alias: &str,
        group_id: &IdentifierPrefix,
        members: &[IdentifierPrefix],
        member_alias: &str,
    ) -> Result<()> {
        self.persist_group_metadata(group_alias, group_id, members, member_alias)
    }

    /// Load the multisig group identifier prefix for an alias.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `group_id` file is missing or invalid.
    pub fn load_multisig_prefix(&self, alias: &str) -> Result<IdentifierPrefix> {
        let s = self.read_file(alias, "group_id")?;
        IdentifierPrefix::from_str(s.trim())
            .map_err(|_| Error::PersistenceError("invalid group_id".into()))
    }

    /// Load the member list for a multisig group alias.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `participants` file is missing or invalid.
    pub fn load_multisig_members(&self, alias: &str) -> Result<Vec<IdentifierPrefix>> {
        let json = self.read_file(alias, "participants")?;
        let strs: Vec<String> = serde_json::from_str(&json)
            .map_err(|e| Error::PersistenceError(format!("invalid participants JSON: {e}")))?;
        strs.iter()
            .map(|s| {
                IdentifierPrefix::from_str(s.trim())
                    .map_err(|_| Error::PersistenceError(format!("invalid participant: {s}")))
            })
            .collect()
    }

    /// Load the member alias for a multisig group (back-reference to the
    /// individual identifier used by this participant).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the `member_alias` file is missing.
    pub fn load_multisig_member_alias(&self, alias: &str) -> Result<String> {
        self.read_file(alias, "member_alias")
            .map(|s| s.trim().to_owned())
    }

    /// List all stored aliases in this store.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the root directory cannot be read.
    pub fn list_aliases(&self) -> Result<Vec<String>> {
        let mut aliases = vec![];
        for entry in std::fs::read_dir(&self.root)
            .map_err(|e| Error::PersistenceError(format!("cannot read store root: {e}")))?
        {
            let entry = entry
                .map_err(|e| Error::PersistenceError(format!("directory entry error: {e}")))?;
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    aliases.push(name.to_owned());
                }
            }
        }
        aliases.sort();
        Ok(aliases)
    }

    // ── Key provider integration (behind `keyprovider` feature) ────────────────

    /// Create an identifier using an external key provider.
    ///
    /// Unlike [`create`](KeriStore::create), this method does **not** generate
    /// or persist any seed material on disk — the key provider handles all
    /// signing. Only the identifier prefix is persisted.
    ///
    /// This is the preferred method for mobile platforms (Android Keystore,
    /// iOS Secure Enclave) where private keys must never leave the OS-level
    /// secure enclave.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] on I/O failures.
    /// - Propagates errors from [`create_identifier`](crate::advanced::operations::create_identifier).
    #[cfg(feature = "keyprovider")]
    pub async fn create_with_provider(
        &self,
        alias: &str,
        provider: std::sync::Arc<dyn keri_keyprovider::KeyProvider>,
        next_public_key: keri_controller::BasicPrefix,
        config: IdentifierConfig,
    ) -> Result<(Identifier, crate::advanced::keyprovider_adapter::KeriSigner)> {
        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;

        let db_path = alias_dir.join("db");

        let controller = self.get_or_create_controller(db_path)?;
        let keri_signer = crate::advanced::keyprovider_adapter::KeriSigner::from(provider);
        let id = crate::advanced::operations::create_identifier_with_controller(
            &controller,
            keri_signer.clone(),
            next_public_key,
            config,
        )
        .await?;

        use keri_core::prefix::CesrPrimitive;
        self.write_file(alias, "id", &id.id().to_str())?;

        Ok((id, keri_signer))
    }

    /// Load an existing identifier and pair it with an external key provider.
    ///
    /// Use this when keys are managed by a platform keystore (Android, iOS)
    /// and the identifier was previously created with
    /// [`create_with_provider`](KeriStore::create_with_provider).
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the alias directory or `id` file is missing.
    /// - [`Error::Controller`] if the database cannot be opened.
    #[cfg(feature = "keyprovider")]
    pub fn load_with_provider(
        &self,
        alias: &str,
        provider: std::sync::Arc<dyn keri_keyprovider::KeyProvider>,
    ) -> Result<(Identifier, crate::advanced::keyprovider_adapter::KeriSigner)> {
        let id = self.load(alias)?;
        let keri_signer = crate::advanced::keyprovider_adapter::KeriSigner::from(provider);
        Ok((id, keri_signer))
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn get_or_create_controller(&self, db_path: PathBuf) -> Result<Arc<Controller>> {
        let mut cache = self.controllers.lock().unwrap();
        if let Some(ctrl) = cache.get(&db_path) {
            return Ok(ctrl.clone());
        }
        let ctrl = Arc::new(Controller::new(db_path.clone())?);
        cache.insert(db_path, ctrl.clone());
        Ok(ctrl)
    }

    /// The cached [`Controller`] for `alias`'s redb (creating + caching
    /// it on first use). Callers minting a delegated AID must build the
    /// request through this controller — see
    /// [`crate::advanced::operations::build_delegation_request_with_controller`] —
    /// so the mint shares the one handle `load`/`finalize` use instead
    /// of opening a second `Database` on the same file.
    pub fn controller_for(&self, alias: &str) -> Result<Arc<Controller>> {
        let db_path = self.alias_dir(alias).join("db");
        self.get_or_create_controller(db_path)
    }

    fn persist_group_metadata(
        &self,
        group_alias: &str,
        group_id: &IdentifierPrefix,
        members: &[IdentifierPrefix],
        member_alias: &str,
    ) -> Result<()> {
        let alias_dir = self.alias_dir(group_alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;

        use keri_core::prefix::CesrPrimitive;
        self.write_file(group_alias, "group_id", &group_id.to_str())?;
        self.write_file(group_alias, "member_alias", member_alias)?;

        let member_strs: Vec<String> = members.iter().map(|p| p.to_str()).collect();
        let json = serde_json::to_string(&member_strs)
            .map_err(|e| Error::PersistenceError(format!("cannot serialise members: {e}")))?;
        self.write_file(group_alias, "participants", &json)?;

        Ok(())
    }

    fn alias_dir(&self, alias: &str) -> PathBuf {
        self.root.join(alias)
    }

    fn write_file(&self, alias: &str, filename: &str, content: &str) -> Result<()> {
        let alias_dir = self.alias_dir(alias);
        std::fs::create_dir_all(&alias_dir)
            .map_err(|e| Error::PersistenceError(format!("cannot create alias dir: {e}")))?;
        let path = alias_dir.join(filename);
        std::fs::write(&path, content)
            .map_err(|e| Error::PersistenceError(format!("cannot write {filename}: {e}")))
    }

    fn read_file(&self, alias: &str, filename: &str) -> Result<String> {
        let path = self.alias_dir(alias).join(filename);
        std::fs::read_to_string(&path)
            .map_err(|e| Error::PersistenceError(format!("cannot read {filename}: {e}")))
    }

    fn load_seed(&self, alias: &str, filename: &str) -> Result<SeedPrefix> {
        let s = self.read_file(alias, filename)?;
        SeedPrefix::from_str(s.trim())
            .map_err(|e| Error::PersistenceError(format!("invalid seed in {filename}: {e}")))
    }
}
