use keri_core::{
    actor::{event_generator, prelude::SelfAddressingIdentifier},
    database::{EscrowCreator, EventDatabase},
    event::{
        event_data::EventData,
        sections::{seal::Seal, KeyConfig},
        KeyEvent,
    },
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice},
    },
    oobi::LocationScheme,
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use keri_core::prefix::CesrPrimitive;
use teliox::registry::RegistryStore;

use crate::identifier::Identifier;

use super::MechanicsError;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Generate and return rotation event for Identifier
    pub async fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        new_next_threshold: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        for wit_oobi in &witness_to_add {
            self.communication.resolve_loc_schema(wit_oobi).await?;
        }

        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(MechanicsError::WrongWitnessPrefixError)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let state = self.known_events.get_state(&self.id)?;

        event_generator::rotate(
            state,
            current_keys,
            new_next_keys,
            new_next_threshold,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
            self.known_events.version,
        )
        .map_err(MechanicsError::generation)
    }

    /// Like [`Identifier::rotate`] but lets the caller set the new
    /// current signature threshold (`kt`) in addition to the new
    /// pre-rotation threshold (`nt`). Use when raising or lowering
    /// the multi-sig threshold; plain `rotate` always emits events
    /// with `kt = 1`.
    pub async fn rotate_with_thresholds(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_signature_threshold: u64,
        new_next_keys: Vec<BasicPrefix>,
        new_next_threshold: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        for wit_oobi in &witness_to_add {
            self.communication.resolve_loc_schema(wit_oobi).await?;
        }
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| match &wit.eid {
                IdentifierPrefix::Basic(bp) => Ok(bp.clone()),
                _ => Err(MechanicsError::WrongWitnessPrefixError),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let state = self.known_events.get_state(&self.id)?;
        event_generator::rotate_with_thresholds(
            state,
            current_keys,
            new_signature_threshold,
            new_next_keys,
            new_next_threshold,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
            self.known_events.version,
        )
        .map_err(MechanicsError::generation)
    }

    /// Generate the event that abandons this identifier. It reveals
    /// `current_keys`, the keys the last establishment event committed to,
    /// and commits to no next keys (`n=[]`, `nt=0`), so the identifier's key
    /// event log is final: witnesses refuse anything after it.
    ///
    /// A delegated identifier gets a `drt`, which its delegator must anchor
    /// like any delegated rotation. `anchors` go into the event's seal
    /// list, e.g. seals approving the abandonment of identifiers this one
    /// delegated. Finish it with [`Self::finalize_rotate`].
    pub async fn abandon(
        &self,
        current_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
        anchors: Vec<Seal>,
    ) -> Result<String, MechanicsError> {
        for wit_oobi in &witness_to_add {
            self.communication.resolve_loc_schema(wit_oobi).await?;
        }
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| match &wit.eid {
                IdentifierPrefix::Basic(bp) => Ok(bp.clone()),
                _ => Err(MechanicsError::WrongWitnessPrefixError),
            })
            .collect::<Result<Vec<_>, _>>()?;
        let state = self.known_events.get_state(&self.id)?;
        let event = event_generator::abandon(
            state,
            current_keys,
            1,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
            anchors,
            self.known_events.version,
        )
        .map_err(MechanicsError::generation)?;
        String::from_utf8(event.encode()?).map_err(|_e| MechanicsError::EventFormatError)
    }

    /// Generate and return interaction event for Identifier
    pub fn anchor(&self, payload: &[SelfAddressingIdentifier]) -> Result<String, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor(
            state,
            payload,
            self.known_events.version,
        )
        .map_err(MechanicsError::generation)
    }

    pub fn anchor_with_seal(
        &self,
        seal_list: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor_with_seal(
            state,
            seal_list,
            self.known_events.version,
        )
        .map_err(MechanicsError::generation)
    }

    pub async fn finalize_rotate(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            // Provide kel for new witnesses
            // TODO  should add to notify_witness instead of sending directly?
            match &ke.data.event_data {
                EventData::Rot(rot) | EventData::Drt(rot) => {
                    let own_kel = self.known_events.find_kel_with_receipts(&self.id).unwrap();
                    for witness in &rot.witness_config.graft {
                        let witness_id = IdentifierPrefix::Basic(witness.clone());
                        for msg in &own_kel {
                            self.communication
                                .send_message_to(
                                    witness_id.clone(),
                                    Message::Notice(msg.clone()),
                                )
                                .await?;
                        }
                    }
                }
                _ => (),
            };
            self.finalize_key_event(&ke, &sig)?;
            Ok(())
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    /// Finalise a rotation event signed by multiple keys.
    ///
    /// `finalize_rotate` accepts a single signature and assumes the
    /// caller is the only signer. That fits the common single-key
    /// AID case, but not a rotation that reveals two or more
    /// previously-committed next-keys at once — for example the
    /// second step of a single-key → multi-sig transition, where
    /// the new current-key set contains keys held on different
    /// devices and each must sign at its own position in the
    /// revealed key list.
    ///
    /// Caller must provide one [`IndexedSignature`] per signing key
    /// whose digest was committed in the prior establishment event,
    /// with both `signing_index` and `prev_next_index` set
    /// correctly. Up to threshold-many signatures are required for
    /// the event to be accepted, but more is also fine — extras are
    /// retained so verifiers reach the threshold deterministically.
    pub async fn finalize_rotate_multi(
        &mut self,
        event: &[u8],
        sigs: Vec<IndexedSignature>,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            // Witness graft: same as `finalize_rotate` — push our
            // KEL to any witness this rotation adds before notifying.
            match &ke.data.event_data {
                EventData::Rot(rot) | EventData::Drt(rot) => {
                    let own_kel = self.known_events.find_kel_with_receipts(&self.id).unwrap();
                    for witness in &rot.witness_config.graft {
                        let witness_id = IdentifierPrefix::Basic(witness.clone());
                        for msg in &own_kel {
                            self.communication
                                .send_message_to(
                                    witness_id.clone(),
                                    Message::Notice(msg.clone()),
                                )
                                .await?;
                        }
                    }
                }
                _ => Err(MechanicsError::WrongEventTypeError)?,
            };
            let signed_message = ke.sign(sigs, None, None);
            self.known_events
                .save(&Message::Notice(Notice::Event(signed_message.clone())))?;
            let st = self.cached_state.clone().apply(&ke)?;
            self.cached_state = st;
            self.to_notify.push(signed_message);
            Ok(())
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    pub async fn finalize_anchor(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            match &ke.data.event_data {
                EventData::Ixn(_) => self.finalize_key_event(&ke, &sig),
                _ => Err(MechanicsError::WrongEventTypeError),
            }
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    /// Multi-signer variant of [`finalize_anchor`].
    ///
    /// Accepts an `ixn` event together with one [`IndexedSignature`] per
    /// participating signer. The signatures are merged, the assembled
    /// signed event is saved to the local KEL and queued for witness
    /// notification. Mirrors [`finalize_rotate_multi`] for interaction
    /// events; used by the cosign coordinator when a delegating `ixn`
    /// must be signed by the full multi-sig threshold before publication.
    pub async fn finalize_anchor_multi(
        &mut self,
        event: &[u8],
        sigs: Vec<IndexedSignature>,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::KeyEvent(ke) = parsed_event {
            match &ke.data.event_data {
                EventData::Ixn(_) => {
                    let signed_message = ke.sign(sigs, None, None);
                    self.known_events
                        .save(&Message::Notice(Notice::Event(signed_message.clone())))?;
                    let st = self.cached_state.clone().apply(&ke)?;
                    self.cached_state = st;
                    self.to_notify.push(signed_message);
                    Ok(())
                }
                _ => Err(MechanicsError::WrongEventTypeError),
            }
        } else {
            Err(MechanicsError::WrongEventTypeError)
        }
    }

    /// Checks signatures and updates database.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function if event is a key event.
    pub(crate) fn finalize_key_event(
        &mut self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        // Not an invariant: the lookup fails whenever this
        // identifier's key material and the KEL have drifted apart, so
        // report it rather than unwinding the caller's task.
        let own_index = self.own_signature_index(event, sig)?;
        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        self.known_events
            .save(&Message::Notice(Notice::Event(signed_message.clone())))?;

        let st = self.cached_state.clone().apply(event)?;
        self.cached_state = st;

        self.to_notify.push(signed_message);

        Ok(())
    }

    pub fn index_in_current_keys(&self, key_config: &KeyConfig) -> Result<usize, MechanicsError> {
        // TODO what if group participant is a group and has more than one
        // public key?
        let own_pk = self.own_or_first_key()?;
        key_config
            .public_keys
            .iter()
            .position(|pk| same_key(pk, &own_pk))
            .ok_or(MechanicsError::NotGroupParticipantError)
    }

    /// The current key of this identifier this controller signs with: the
    /// one given to `set_own_key`, while it is still a current key, or the
    /// only current key. `None` when the identifier has several current
    /// keys and none is known to be this controller's.
    pub(crate) fn own_public_key(&self) -> Result<Option<BasicPrefix>, MechanicsError> {
        let current = self.known_events.current_public_keys(&self.id)?;
        if let Some(own) = &self.own_key {
            if let Some(pk) = current.iter().find(|pk| same_key(pk, own)) {
                return Ok(Some(pk.clone()));
            }
        }
        Ok(match current.as_slice() {
            [only] => Some(only.clone()),
            _ => None,
        })
    }

    /// [`Self::own_public_key`], or the first current key when it is not
    /// known: what an identifier with one key, or one controller holding
    /// all of them, signs with.
    fn own_or_first_key(&self) -> Result<BasicPrefix, MechanicsError> {
        match self.own_public_key()? {
            Some(pk) => Ok(pk),
            None => self
                .known_events
                .current_public_keys(&self.id)?
                .first()
                .cloned()
                .ok_or_else(|| MechanicsError::IdentifierAbandoned(self.id.clone())),
        }
    }

    /// The index `sig` signs `event` at: the position of the key it
    /// verifies against among the keys that sign the event. Falls back to
    /// [`Self::get_index`] when no key verifies it, leaving the refusal to
    /// the event's own verification.
    pub(crate) fn own_signature_index(
        &self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
    ) -> Result<usize, MechanicsError> {
        // Nothing signs for an abandoned identifier, whichever key it uses.
        let prefix = event.data.get_prefix();
        if self
            .known_events
            .get_state(&prefix)
            .is_ok_and(|state| state.is_abandoned())
        {
            return Err(MechanicsError::IdentifierAbandoned(prefix));
        }
        let signing_keys = match &event.data.event_data {
            EventData::Icp(icp) => icp.key_config.public_keys.clone(),
            EventData::Dip(dip) => dip.inception_data.key_config.public_keys.clone(),
            EventData::Rot(rot) | EventData::Drt(rot) => rot.key_config.public_keys.clone(),
            EventData::Ixn(_) => self.known_events.current_public_keys(&prefix)?,
        };
        match signature_index(&signing_keys, &event.encode()?, sig) {
            Some(index) => Ok(index),
            None => self.get_index(&event.data),
        }
    }

    /// Helper function for getting the position of identifier's public key in
    /// group's current keys list.
    ///
    /// For `Rot`/`Drt`, two member states are accepted: the member has
    /// already rotated locally and now reveals their current public key
    /// (so the match is by `current_public_keys`), or the member has
    /// not yet rotated locally and the event reveals their pre-committed
    /// next-key (so the match is by `next_keys_hashes`).
    pub(crate) fn get_index(&self, key_event: &KeyEvent) -> Result<usize, MechanicsError> {
        match &key_event.event_data {
            EventData::Icp(icp) => self.index_in_current_keys(&icp.key_config),
            EventData::Rot(rot) => self.index_in_rotation(&rot.key_config),
            EventData::Dip(dip) => self.index_in_current_keys(&dip.inception_data.key_config),
            EventData::Drt(drt) => self.index_in_rotation(&drt.key_config),
            EventData::Ixn(_ixn) => {
                let own_pk = self.own_or_first_key()?;
                self.known_events
                    .current_public_keys(&key_event.get_prefix())?
                    .iter()
                    .position(|pk| same_key(pk, &own_pk))
                    .ok_or(MechanicsError::NotGroupParticipantError)
            }
        }
    }

    fn index_in_rotation(&self, key_config: &KeyConfig) -> Result<usize, MechanicsError> {
        let own_pk = self.own_or_first_key()?;
        if let Some(pos) = key_config
            .public_keys
            .iter()
            .position(|pk| same_key(pk, &own_pk))
        {
            return Ok(pos);
        }
        // The next key committed at this controller's own position. An
        // abandoned member has no next key that could be revealed.
        let own_position = self
            .known_events
            .current_public_keys(&self.id)?
            .iter()
            .position(|pk| same_key(pk, &own_pk))
            .unwrap_or(0);
        let own_npk = self
            .known_events
            .next_keys_hashes(&self.id)?
            .into_iter()
            .nth(own_position)
            .ok_or_else(|| MechanicsError::IdentifierAbandoned(self.id.clone()))?;
        key_config
            .public_keys
            .iter()
            .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            .ok_or(MechanicsError::NotGroupParticipantError)
    }
}

/// Whether `a` and `b` are the same public key, in either CESR encoding: a
/// key committed non-transferable and the same key in a transferable
/// identifier's event are different strings for one signer.
fn same_key(a: &BasicPrefix, b: &BasicPrefix) -> bool {
    a == b || (a.signing_code() == b.signing_code() && a.derivative() == b.derivative())
}

/// The position among `keys` of the key `sig` over `data` verifies against.
pub(crate) fn signature_index(
    keys: &[BasicPrefix],
    data: &[u8],
    sig: &SelfSigningPrefix,
) -> Option<usize> {
    keys.iter()
        .position(|pk| pk.verify(data, sig).unwrap_or(false))
}
