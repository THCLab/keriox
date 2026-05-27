use keri_core::{
    actor::{event_generator, MaterialPath},
    database::{EscrowCreator, EventDatabase},
    event::{
        sections::{seal::Seal, threshold::SignatureThreshold},
        KeyEvent,
    },
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signature::{Signature, SignerData},
        signed_event_message::{Message, Op},
        EventTypeTag,
    },
    mailbox::exchange::{Exchange, ForwardTopic, SignedExchange},
    oobi::LocationScheme,
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};
use said::SelfAddressingIdentifier;
use teliox::database::TelEventDatabase;

use crate::identifier::Identifier;

use super::MechanicsError;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Init group identifier
    ///
    /// Returns serialized group icp and list of exchange messages to sign.
    /// Exchanges are meant to be send to witness and forwarded to group
    /// participants.
    /// If `delegator` parameter is provided, it will generate delegated
    /// inception and append delegation request to exchange messages.
    pub fn incept_group(
        &self,
        participants: Vec<IdentifierPrefix>,
        signature_threshold: u64,
        next_keys_threshold: Option<u64>,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<IdentifierPrefix>,
    ) -> Result<(String, Vec<String>), MechanicsError> {
        let key_config = self
            .known_events
            .storage
            .get_state(&self.id)
            .ok_or(MechanicsError::UnknownIdentifierError(self.id.clone()))?
            .current;

        let mut pks = key_config.public_keys;
        let mut npks = key_config.next_keys_data.next_keys_hashes();
        for participant in &participants {
            let state = self
                .known_events
                .storage
                .get_state(participant)
                .ok_or(MechanicsError::UnknownIdentifierError(participant.clone()))?;
            pks.append(&mut state.clone().current.public_keys);
            npks.append(&mut state.clone().current.next_keys_data.next_keys_hashes());
        }

        let current_sig_threshold = SignatureThreshold::Simple(signature_threshold);
        let next_sig_threshold = next_keys_threshold
            .map(|sig| SignatureThreshold::Simple(sig))
            .unwrap_or(current_sig_threshold.clone());
        let icp = event_generator::incept_with_next_hashes(
            pks,
            &current_sig_threshold,
            npks,
            &next_sig_threshold,
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
            delegator.as_ref(),
        )?;

        let serialized_icp = String::from_utf8(icp.encode()?)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let mut exchanges = participants
            .iter()
            .map(|id| -> Result<_, _> {
                let exn = event_generator::exchange(id, &icp, ForwardTopic::Multisig).encode()?;
                String::from_utf8(exn).map_err(|_e| MechanicsError::EventFormatError)
            })
            .collect::<Result<Vec<String>, MechanicsError>>()?;

        if let Some(delegator) = delegator {
            let delegation_request = String::from_utf8(
                event_generator::exchange(&delegator, &icp, ForwardTopic::Delegate).encode()?,
            )
            .map_err(|_e| MechanicsError::EventFormatError)?;
            exchanges.push(delegation_request);
        }

        Ok((serialized_icp, exchanges))
    }

    /// Build a rotation event for an established group identifier and the
    /// exchange messages addressed to each remaining co-signer.
    ///
    /// `new_participants` is the full post-rotation member set; pass the
    /// same set with one member removed to evict a device. The caller
    /// (`self.id`) does not need to appear in the list (self-eviction is
    /// permitted) but, if absent, must currently be in the group's key set
    /// — otherwise `NotGroupParticipantError` is returned.
    ///
    /// Per-member next-key digests are read from each participant's local
    /// state, so callers must ensure participants' KELs are up to date
    /// before invocation.
    ///
    /// Returns `(serialized_rot, exchanges)` analogous to [`incept_group`].
    pub async fn rotate_group(
        &self,
        group_id: &IdentifierPrefix,
        new_participants: Vec<IdentifierPrefix>,
        new_signature_threshold: u64,
        new_next_threshold: Option<u64>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: Option<u64>,
    ) -> Result<(String, Vec<String>), MechanicsError> {
        let group_state = self
            .known_events
            .storage
            .get_state(group_id)
            .ok_or_else(|| MechanicsError::UnknownIdentifierError(group_id.clone()))?;

        let own_pk = self
            .known_events
            .current_public_keys(&self.id)?
            .into_iter()
            .next()
            .ok_or(MechanicsError::NotGroupParticipantError)?;
        let is_current_member = group_state
            .current
            .public_keys
            .iter()
            .any(|pk| pk == &own_pk);
        let is_pre_committed = group_state
            .current
            .next_keys_data
            .next_keys_hashes()
            .iter()
            .any(|nk| nk.verify_binding(own_pk.to_str().as_bytes()));
        if !is_current_member && !is_pre_committed {
            return Err(MechanicsError::NotGroupParticipantError);
        }

        let mut pks: Vec<BasicPrefix> = Vec::with_capacity(new_participants.len());
        let mut npks: Vec<SelfAddressingIdentifier> = Vec::with_capacity(new_participants.len());
        for participant in &new_participants {
            let state = self
                .known_events
                .storage
                .get_state(participant)
                .ok_or_else(|| MechanicsError::UnknownIdentifierError(participant.clone()))?;
            pks.extend(state.current.public_keys.clone());
            npks.extend(state.current.next_keys_data.next_keys_hashes());
        }

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

        let current_witness_threshold = match &group_state.witness_config.tally {
            SignatureThreshold::Simple(t) => *t,
            SignatureThreshold::Weighted(_) => 0,
        };
        let next_threshold = new_next_threshold.unwrap_or(new_signature_threshold);
        let wit_threshold = witness_threshold.unwrap_or(current_witness_threshold);

        let rot = event_generator::rotate_with_next_hashes(
            group_state,
            pks,
            npks,
            new_signature_threshold,
            next_threshold,
            witnesses_to_add,
            witness_to_remove,
            wit_threshold,
        )
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let serialized_rot = String::from_utf8(rot.encode()?)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let exchanges = new_participants
            .iter()
            .filter(|id| *id != &self.id)
            .map(|id| -> Result<_, _> {
                let exn = event_generator::exchange(id, &rot, ForwardTopic::Multisig).encode()?;
                String::from_utf8(exn).map_err(|_e| MechanicsError::EventFormatError)
            })
            .collect::<Result<Vec<String>, MechanicsError>>()?;

        Ok((serialized_rot, exchanges))
    }

    /// Build an interaction event on an established group identifier
    /// anchoring the supplied SAID seals, plus the forward exchanges
    /// addressed to the remaining co-signers.
    ///
    /// The caller (`self.id`) must currently be a signer of the
    /// group — i.e. their individual current public key must appear
    /// in the group's current key set. Anchors do not advance the
    /// group's key state, so unlike `rotate_group` no
    /// pre-rotation-digest fallback is accepted.
    ///
    /// `participants` is the full member list of the group (the
    /// caller may or may not be in it; the caller is filtered out of
    /// the returned exchanges either way).
    ///
    /// Returns `(serialized_ixn, exchanges)`.
    pub fn anchor_group(
        &self,
        group_id: &IdentifierPrefix,
        anchors: &[SelfAddressingIdentifier],
        participants: &[IdentifierPrefix],
    ) -> Result<(String, Vec<String>), MechanicsError> {
        let seals: Vec<Seal> = anchors
            .iter()
            .map(|sai| {
                Seal::Digest(keri_core::event::sections::seal::DigestSeal::new(
                    sai.clone(),
                ))
            })
            .collect();
        self.anchor_group_with_seals(group_id, &seals, participants)
    }

    /// Same as [`anchor_group`] but accepts arbitrary `Seal` variants
    /// (used by the delegator-side `ixn` that anchors a delegated
    /// inception's event seal).
    pub fn anchor_group_with_seals(
        &self,
        group_id: &IdentifierPrefix,
        seals: &[Seal],
        participants: &[IdentifierPrefix],
    ) -> Result<(String, Vec<String>), MechanicsError> {
        let group_state = self
            .known_events
            .storage
            .get_state(group_id)
            .ok_or_else(|| MechanicsError::UnknownIdentifierError(group_id.clone()))?;

        let own_pk = self
            .known_events
            .current_public_keys(&self.id)?
            .into_iter()
            .next()
            .ok_or(MechanicsError::NotGroupParticipantError)?;
        if !group_state
            .current
            .public_keys
            .iter()
            .any(|pk| pk == &own_pk)
        {
            return Err(MechanicsError::NotGroupParticipantError);
        }

        let ixn = event_generator::anchor_with_seal(group_state, seals)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let serialized_ixn = String::from_utf8(ixn.encode()?)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))?;

        let exchanges = participants
            .iter()
            .filter(|id| *id != &self.id)
            .map(|id| -> Result<_, _> {
                let exn = event_generator::exchange(id, &ixn, ForwardTopic::Multisig).encode()?;
                String::from_utf8(exn).map_err(|_e| MechanicsError::EventFormatError)
            })
            .collect::<Result<Vec<String>, MechanicsError>>()?;

        Ok((serialized_ixn, exchanges))
    }

    /// Finalizes group identifier.
    pub async fn finalize_group_incept(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, Signature)>,
    ) -> Result<IdentifierPrefix, MechanicsError> {
        // Join icp event with signature
        let key_event =
            parse_event_type(group_event).map_err(|_e| MechanicsError::EventFormatError)?;
        let ke = if let EventType::KeyEvent(icp) = key_event {
            match icp.event_type {
                EventTypeTag::Icp | EventTypeTag::Dip => icp,
                _ => Err(MechanicsError::InceptionError(
                    "Event is not inception".to_string(),
                ))?,
            }
        } else {
            return Err(MechanicsError::WrongEventTypeError);
        };
        let group_prefix = ke.data.get_prefix();
        self.finalize_event(&ke, sig, exchanges).await?;
        Ok(group_prefix)
    }

    /// Finalizes group event.
    pub async fn finalize_group_event(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, Signature)>,
    ) -> Result<(), MechanicsError> {
        // Join icp event with signature
        let key_event =
            parse_event_type(group_event).map_err(|_e| MechanicsError::EventFormatError)?;
        let ke = if let EventType::KeyEvent(icp) = key_event {
            icp
        } else {
            return Err(MechanicsError::WrongEventTypeError);
        };
        self.finalize_event(&ke, sig, exchanges).await?;
        Ok(())
    }

    /// Finalizes group event.
    /// Joins event with signature and verifies them.
    async fn finalize_event(
        &mut self,
        key_event: &KeriEvent<KeyEvent>,
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, Signature)>,
    ) -> Result<(), MechanicsError> {
        let own_index = self.get_index(&key_event.data)?;

        self.known_events
            .finalize_key_event(&key_event, &sig, own_index)?;

        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = key_event.sign(vec![signature], None, None);
        self.to_notify.push(signed_message);

        let att_signature = IndexedSignature::new_both_same(sig, own_index as u16);

        for (exn, signature) in exchanges {
            self.finalize_exchange(&exn, signature, att_signature.clone())
                .await?;
        }
        Ok(())
    }

    pub async fn finalize_exchange(
        &self,
        exchange: &[u8],
        exn_signature: Signature,
        data_signature: IndexedSignature,
    ) -> Result<(), MechanicsError> {
        // Join exn messages with their signatures and send it to witness.
        let material_path = MaterialPath::create_from_str("-a".into());
        // let attached_sig = sigs;
        let parsed_exn =
            parse_event_type(exchange).map_err(|_e| MechanicsError::EventFormatError)?;
        if let EventType::Exn(exn) = parsed_exn {
            let Exchange::Fwd {
                args: _,
                to_forward,
            } = exn.data.data.clone();

            let sigs: Vec<_> = if let Some(receipts) = self.known_events.find_receipt(
                &to_forward.data.get_prefix(),
                to_forward.data.get_sn(),
                &to_forward.digest()?,
            )? {
                receipts
                    .signatures
                    .iter()
                    .map(|c| Signature::NonTransferable(c.clone()))
                    .chain([Signature::Transferable(
                        SignerData::JustSignatures,
                        vec![data_signature],
                    )])
                    .collect::<Vec<_>>()
            } else {
                vec![Signature::Transferable(
                    SignerData::JustSignatures,
                    vec![data_signature],
                )]
            };

            let signer_exn = Message::Op(Op::Exchange(SignedExchange {
                exchange_message: exn,
                signature: vec![exn_signature],
                data_signature: (material_path.clone(), sigs.clone()),
            }));
            // `get_state_at_event` re-applies the forwarded event to the
            // local state, which returns DuplicateError when the event has
            // already been finalized (the common case during group
            // rotations). Fall back to the post-application state — its
            // witness config already reflects the event.
            let wits = match self.known_events.get_state_at_event(&to_forward) {
                Ok(state) => state.witness_config.witnesses,
                Err(_) => self
                    .known_events
                    .storage
                    .get_state(&to_forward.data.get_prefix())
                    .map(|st| st.witness_config.witnesses)
                    .unwrap_or_default(),
            };
            // TODO for now get first witness
            if let Some(wit) = wits.first() {
                self.communication
                    .send_message_to(
                        IdentifierPrefix::Basic(wit.clone()),
                        keri_core::oobi::Scheme::Http,
                        signer_exn,
                    )
                    .await?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }
}
