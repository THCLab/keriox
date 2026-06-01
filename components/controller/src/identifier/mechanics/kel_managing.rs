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
    oobi::{LocationScheme, Scheme},
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use keri_core::prefix::CesrPrimitive;
use teliox::database::TelEventDatabase;

use crate::identifier::Identifier;

use super::MechanicsError;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
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
        )
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    /// Generate and return interaction event for Identifier
    pub fn anchor(&self, payload: &[SelfAddressingIdentifier]) -> Result<String, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor(state, payload)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    pub fn anchor_with_seal(
        &self,
        seal_list: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, MechanicsError> {
        let state = self.known_events.get_state(&self.id)?;
        event_generator::anchor_with_seal(state, seal_list)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
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
                                    Scheme::Http,
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
                                    Scheme::Http,
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

    /// Checks signatures and updates database.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function if event is a key event.
    pub(crate) fn finalize_key_event(
        &mut self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let own_index = self.get_index(&event.data).unwrap();
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
        let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
        key_config
            .public_keys
            .iter()
            .position(|pk| pk.eq(&own_pk))
            .ok_or(MechanicsError::NotGroupParticipantError)
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
                let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
                self.known_events
                    .current_public_keys(&key_event.get_prefix())?
                    .iter()
                    .position(|pk| pk.eq(&own_pk))
                    .ok_or(MechanicsError::NotGroupParticipantError)
            }
        }
    }

    fn index_in_rotation(&self, key_config: &KeyConfig) -> Result<usize, MechanicsError> {
        let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
        if let Some(pos) = key_config.public_keys.iter().position(|pk| pk == &own_pk) {
            return Ok(pos);
        }
        let own_npk = self.known_events.next_keys_hashes(&self.id)?[0].clone();
        key_config
            .public_keys
            .iter()
            .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            .ok_or(MechanicsError::NotGroupParticipantError)
    }
}
