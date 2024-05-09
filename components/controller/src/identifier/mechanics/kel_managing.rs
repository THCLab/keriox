use keri_core::{
    actor::{event_generator, prelude::SelfAddressingIdentifier},
    event::{event_data::EventData, sections::seal::Seal, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice},
    },
    oobi::{LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use keri_core::prefix::CesrPrimitive;

use crate::identifier::Identifier;

use super::MechanicsError;

impl Identifier {
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
                                    &witness_id,
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

    /// Helper function for getting the position of identifier's public key in
    /// group's current keys list.
    pub(crate) fn get_index(&self, key_event: &KeyEvent) -> Result<usize, MechanicsError> {
        match &key_event.event_data {
            EventData::Icp(icp) => {
                // TODO what if group participant is a group and has more than one
                // public key?
                let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
                icp.key_config
                    .public_keys
                    .iter()
                    .position(|pk| pk.eq(&own_pk))
            }
            EventData::Rot(rot) => {
                let own_npk = &self.known_events.next_keys_hashes(&self.id)?[0];
                rot.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            }
            EventData::Dip(dip) => {
                // TODO what if group participant is a group and has more than one
                // public key?
                let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
                dip.inception_data
                    .key_config
                    .public_keys
                    .iter()
                    .position(|pk| pk.eq(&own_pk))
            }
            EventData::Drt(drt) => {
                let own_npk = &self.known_events.next_keys_hashes(&self.id)?[0];
                drt.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            }
            EventData::Ixn(_ixn) => {
                let own_pk = self.known_events.current_public_keys(&self.id)?[0].clone();
                self.known_events
                    .current_public_keys(&key_event.get_prefix())?
                    .iter()
                    .position(|pk| pk.eq(&own_pk))
            }
        }
        .ok_or(MechanicsError::NotGroupParticipantError)
    }
}
