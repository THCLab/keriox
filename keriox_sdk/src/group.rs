//! Group identities (KERI multisig): one identity controlled by several
//! members, with a signing threshold.
//!
//! A group is created by one member ([`crate::Identity::new_group`]) and
//! joined by the others ([`GroupRequest::accept_as`] via
//! [`crate::Identity::pending_requests`]). All members coordinate through
//! their shared witness's mailbox; the facade handles every event, exchange
//! message and mailbox round internally.

use std::sync::Arc;
use std::time::{Duration, Instant};

use keri_controller::IdentifierPrefix;

use crate::error::{Error, Result};
use crate::ids::{CredentialId, IdentityId};
use crate::keri::KeriInner;
use crate::message::SignedMessage;

/// Builder for a new group. Created by [`crate::Identity::new_group`].
pub struct GroupBuilder {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) member_alias: String,
    pub(crate) group_alias: String,
    pub(crate) members: Vec<IdentityId>,
    pub(crate) threshold: Option<u64>,
}

impl GroupBuilder {
    /// Add another member (import them first with
    /// [`crate::Keri::import_contact`] so their key history is known).
    pub fn member(mut self, id: &IdentityId) -> Self {
        self.members.push(id.clone());
        self
    }

    /// How many members must sign group events (default: all members).
    pub fn threshold(mut self, threshold: u64) -> Self {
        self.threshold = Some(threshold);
        self
    }

    /// Create the group and invite the other members (they receive a
    /// [`GroupRequest`] via their `pending_requests()`). Returns a
    /// handle to await the group becoming ready once everyone accepted.
    pub async fn initiate(self) -> Result<GroupInvite> {
        if self.members.is_empty() {
            return Err(Error::InvalidInput {
                expected: "at least one other member",
                cause: "a group needs more than its creator; add .member(&id)".into(),
            });
        }
        if self.keri.root.join(&self.group_alias).exists() {
            return Err(Error::IdentityExists(self.group_alias));
        }

        // The initiator's database must know every member's key history.
        for member in &self.members {
            self.keri
                .copy_kel_into(&self.member_alias, member.as_prefix())?;
        }

        // The group inherits the initiator's witnesses.
        let member_identifier = self.keri.store.load(&self.member_alias)?;
        let mut witnesses = vec![];
        for witness in member_identifier.witnesses() {
            witnesses.extend(
                member_identifier
                    .get_location(&IdentifierPrefix::Basic(witness))
                    .unwrap_or_default(),
            );
        }
        if witnesses.is_empty() {
            return Err(Error::InvalidInput {
                expected: "initiator identity with at least one witness",
                cause: "group coordination travels through the witness mailbox".into(),
            });
        }
        let witness_threshold = witnesses.len() as u64;

        let total_members = self.members.len() as u64 + 1;
        let threshold = self.threshold.unwrap_or(total_members);

        let config = crate::advanced::types::MultisigConfig {
            members: self.members.iter().map(|m| m.as_prefix().clone()).collect(),
            threshold,
            witnesses,
            witness_threshold,
            delegator: None,
        };
        let group_id = self
            .keri
            .store
            .create_multisig_group(&self.group_alias, &self.member_alias, config)
            .await?;

        // Persist the full member set in the group's key-list order
        // (initiator first, then the invited members) — rotations must
        // reproduce this exact order to keep key indices stable.
        let mut all_members: Vec<IdentifierPrefix> = vec![member_identifier.id().clone()];
        all_members.extend(self.members.iter().map(|m| m.as_prefix().clone()));
        self.keri.store.save_multisig(
            &self.group_alias,
            &group_id,
            &all_members,
            &self.member_alias,
        )?;

        Ok(GroupInvite {
            keri: self.keri,
            group_alias: self.group_alias,
            member_alias: self.member_alias,
            group_id,
        })
    }
}

/// An initiated group waiting for the other members to accept.
pub struct GroupInvite {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) group_alias: String,
    pub(crate) member_alias: String,
    pub(crate) group_id: IdentifierPrefix,
}

impl GroupInvite {
    /// The id the group identity will have.
    pub fn group_id(&self) -> IdentityId {
        IdentityId::from(self.group_id.clone())
    }

    /// Wait until every member has accepted and the group is usable.
    /// Polls the witness mailbox until `timeout` elapses.
    pub async fn wait_ready(self, timeout: Duration) -> Result<Group> {
        let deadline = Instant::now() + timeout;
        let signer = self.keri.store.load_signer(&self.member_alias)?;
        loop {
            let mut member = self.keri.store.load(&self.member_alias)?;
            // Collect co-signatures and receipts from the mailbox.
            let _ = crate::advanced::operations::sync_multisig(&mut member, &signer, &self.group_id)
                .await;
            if member.find_state(&self.group_id).is_ok() {
                return Ok(Group {
                    keri: self.keri,
                    group_alias: self.group_alias,
                    member_alias: self.member_alias,
                    group_id: self.group_id,
                });
            }
            if Instant::now() >= deadline {
                return Err(Error::PendingApproval {
                    what: format!(
                        "group {} membership; not all members accepted within {timeout:?}",
                        self.group_id
                    ),
                });
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }
}

/// A group identity this store participates in.
///
/// Obtain it from [`GroupInvite::wait_ready`] (initiator),
/// [`GroupRequest::accept_as`] (joiner), or [`crate::Keri::group`]
/// (reload in a later session).
pub struct Group {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) group_alias: String,
    pub(crate) member_alias: String,
    pub(crate) group_id: IdentifierPrefix,
}

impl Group {
    /// The group's globally unique id.
    pub fn id(&self) -> IdentityId {
        IdentityId::from(self.group_id.clone())
    }

    /// The local alias of this group.
    pub fn alias(&self) -> &str {
        &self.group_alias
    }

    /// The members known locally (always complete on the initiator side).
    pub fn members(&self) -> Result<Vec<IdentityId>> {
        Ok(self
            .keri
            .store
            .load_multisig_members(&self.group_alias)?
            .into_iter()
            .map(IdentityId::from)
            .collect())
    }

    /// Sign a payload on the group's behalf with this member's key.
    ///
    /// The message verifies once the group's signing threshold is met — with
    /// a threshold of 1, immediately. (Thresholds above 1 need every
    /// signer's signature collected on the same payload; that flow lives in
    /// `advanced::multisig` for now.)
    pub async fn sign(&self, payload: &[u8]) -> Result<SignedMessage> {
        let signer = self.keri.store.load_signer(&self.member_alias)?;
        let member = self.keri.store.load(&self.member_alias)?;
        let group = self.group_identifier()?;

        // This member's position in the group's current key list.
        let member_key = member
            .find_state(member.id())?
            .current
            .public_keys
            .into_iter()
            .next()
            .ok_or(Error::InvalidInput {
                expected: "member identity with a current key",
                cause: "no current public key on record".into(),
            })?;
        let index = group
            .find_state(&self.group_id)?
            .current
            .public_keys
            .iter()
            .position(|k| k == &member_key)
            .ok_or(Error::InvalidInput {
                expected: "membership in the group's current key set",
                cause: "this member's key is not part of the group (rotated out?)".into(),
            })? as u16;

        let json_payload = crate::advanced::signing::wrap_payload(payload)?;
        let raw = signer
            .sign(json_payload.as_bytes())
            .map_err(|e| crate::advanced::Error::Signing(e.to_string()))?;
        let signature = keri_controller::SelfSigningPrefix::new(signer.signing_code(), raw);
        let cesr = group.sign_with_index_to_cesr(&json_payload, signature, index)?;

        Ok(SignedMessage {
            cesr,
            signer: self.id(),
        })
    }

    /// Issue a credential from the group's registry (created automatically
    /// on first use). With a signing threshold above 1, the other members
    /// must co-sign: they see it in [`crate::Identity::pending_requests`] and accept.
    pub async fn issue(&self, payload: &[u8]) -> Result<crate::credential::Credential> {
        let signer = self.keri.store.load_signer(&self.member_alias)?;
        let member_id = self.keri.store.load(&self.member_alias)?.id().clone();

        let registry = match self.registry_id()? {
            Some(r) => r,
            None => {
                let mut group = self.group_identifier()?;
                let (registry, _digest) = crate::advanced::operations::incept_group_registry(
                    &mut group, &member_id, &signer,
                )
                .await?;
                self.keri.store.save_registry(&self.group_alias, &registry)?;
                // Publish the anchoring event and collect witness receipts
                // so the registry becomes fully accepted.
                group.notify_witnesses().await.map_err(crate::advanced::Error::from)?;
                self.sync().await?;
                registry
            }
        };

        let (payload, said) = crate::identity::prepare_credential_payload(payload)?;
        let mut group = self.group_identifier()?;
        crate::advanced::operations::issue_group(&mut group, &member_id, &signer, said.clone())
            .await?;
        group.notify_witnesses().await.map_err(crate::advanced::Error::from)?;
        self.sync().await?;

        Ok(crate::credential::Credential {
            id: CredentialId::new(registry, said),
            payload,
            issuer: self.id(),
        })
    }

    /// Rotate the group's keys (initiator side).
    ///
    /// The group's next keys are the members' pre-committed next keys, so
    /// **every other member must rotate their own identity first** (their
    /// [`crate::Identity::rotate`]); then the initiator calls this, which
    /// rotates the initiator's own keys and publishes the group rotation.
    /// The other members co-sign via [`crate::Identity::pending_requests`].
    pub async fn rotate(&self) -> Result<()> {
        // The rotation event names every member's *new* public key, so the
        // other members' rotated histories must be known locally first.
        let keri = crate::Keri::from_inner(self.keri.clone());
        keri.refresh_contacts().await;
        for alias in self.keri.contact_alias_names() {
            if let Ok(contact) = self.keri.store.load(&alias) {
                let _ = self.keri.copy_kel_into(&self.member_alias, contact.id());
            }
        }

        // Member key roll first: the group's next-key commitment points at
        // this member's (previously) next key.
        self.keri.store.rotate(&self.member_alias).await?;

        let members = self.keri.store.load_multisig_members(&self.group_alias)?;
        let threshold = self
            .group_identifier()?
            .find_state(&self.group_id)?
            .current
            .threshold
            .clone();
        let threshold = match threshold {
            keri_core::event::sections::threshold::SignatureThreshold::Simple(t) => t,
            other => {
                return Err(Error::InvalidInput {
                    expected: "simple numeric group threshold",
                    cause: format!(
                        "weighted thresholds ({other:?}) are supported via advanced:: only"
                    ),
                })
            }
        };

        let config = crate::advanced::types::GroupRotationConfig {
            new_participants: members,
            new_signature_threshold: threshold,
            new_next_threshold: None,
            witness_to_add: vec![],
            witness_to_remove: vec![],
            witness_threshold: None,
        };
        self.keri
            .store
            .rotate_multisig_group(&self.group_alias, config)
            .await?;
        Ok(())
    }

    /// Bring local group state up to date: collect other members'
    /// signatures and witness receipts from the mailbox, and pull any group
    /// events (e.g. rotations published by another member) from the
    /// witnesses' copy of the group's key log.
    pub async fn sync(&self) -> Result<()> {
        let signer = self.keri.store.load_signer(&self.member_alias)?;
        let mut member = self.keri.store.load(&self.member_alias)?;
        crate::advanced::operations::sync_multisig(&mut member, &signer, &self.group_id).await?;

        // Mailbox delivery only covers events addressed to this member;
        // events another member published directly (with their authority)
        // live in the witnesses' group KEL — fetch those too.
        let witnesses: Vec<_> = member.witnesses().collect();
        for witness in witnesses {
            let locations = member
                .get_location(&IdentifierPrefix::Basic(witness))
                .unwrap_or_default();
            for location in locations {
                let Ok(ephemeral) = crate::advanced::EphemeralIdentifier::new() else {
                    continue;
                };
                if let Ok(Some(kel)) = ephemeral
                    .pull_kel(&self.group_id, 0, 100, &location)
                    .await
                {
                    let controller = self.keri.store.controller_for(&self.member_alias)?;
                    let _ = controller.process_kel_stream(kel.concat().as_bytes());
                }
            }
        }
        Ok(())
    }

    /// The group-bound identifier handle (escape hatch + internal use).
    fn group_identifier(&self) -> Result<crate::advanced::Identifier> {
        let controller = self.keri.store.controller_for(&self.member_alias)?;
        Ok(controller.load_identifier(self.group_id.clone(), self.registry_id()?))
    }

    fn registry_id(&self) -> Result<Option<IdentifierPrefix>> {
        let Some(content) = self.keri.store.read_meta(&self.group_alias, "reg_id")? else {
            return Ok(None);
        };
        Ok(content.trim().parse().ok())
    }
}

/// A group request found in [`crate::Identity::pending_requests`]: either
/// an invitation to a new group, or a group event (key rotation, credential
/// issuance, …) started by another member that needs this member's
/// co-signature.
pub struct GroupRequest {
    pub(crate) keri: Arc<KeriInner>,
    /// The receiving member's alias.
    pub(crate) member_alias: String,
    pub(crate) inner: crate::advanced::types::MultisigRequest,
}

impl GroupRequest {
    /// The id of the group this request concerns.
    pub fn group_id(&self) -> IdentityId {
        IdentityId::from(self.inner.group_prefix())
    }

    /// `true` for an invitation to a new group (accept with
    /// [`accept_as`](Self::accept_as)); `false` for an event of a group you
    /// already belong to (accept with [`accept`](Self::accept)).
    pub fn is_invitation(&self) -> bool {
        self.inner.is_inception()
    }

    /// Whether this is a group key rotation. Rotate your own identity
    /// ([`crate::Identity::rotate`]) before accepting one — the group's new
    /// keys are the members' pre-committed next keys.
    pub fn is_rotation(&self) -> bool {
        !self.inner.is_inception()
    }

    /// Accept an invitation and store the group under `group_alias`.
    /// Returns the joined [`Group`] once membership is synchronized.
    pub async fn accept_as(self, group_alias: &str) -> Result<Group> {
        let group_id = self.inner.group_prefix();
        let member_alias = self.member_alias.clone();
        self.co_sign().await?;

        // Record what we know about the group locally.
        let member = self.keri.store.load(&member_alias)?;
        let members = vec![member.id().clone()];
        self.keri
            .store
            .save_multisig(group_alias, &group_id, &members, &member_alias)?;

        Ok(Group {
            keri: self.keri,
            group_alias: group_alias.to_string(),
            member_alias,
            group_id,
        })
    }

    /// Co-sign an event of a group this store already belongs to.
    pub async fn accept(self) -> Result<()> {
        self.co_sign().await
    }

    async fn co_sign(&self) -> Result<()> {
        let group_id = self.inner.group_prefix();
        let signer = self.keri.store.load_signer(&self.member_alias)?;

        // Validating group events needs the other members' key histories;
        // copy everything this store knows into our database.
        for alias in self.keri.contact_alias_names() {
            if let Ok(contact) = self.keri.store.load(&alias) {
                let _ = self.keri.copy_kel_into(&self.member_alias, contact.id());
            }
        }

        let mut member = self.keri.store.load(&self.member_alias)?;
        crate::advanced::operations::accept_multisig(&mut member, &signer, self.inner.clone())
            .await?;
        crate::advanced::operations::sync_multisig(&mut member, &signer, &group_id).await?;
        Ok(())
    }
}
