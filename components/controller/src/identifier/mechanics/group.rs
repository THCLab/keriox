use keri_core::{
    actor::{event_generator, MaterialPath},
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signature::{Signature, SignerData},
        signed_event_message::{Message, Op},
        EventTypeTag,
    },
    mailbox::exchange::{Exchange, ForwardTopic, SignedExchange},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use crate::identifier::Identifier;

use super::MechanicsError;

impl Identifier {
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
        let material_path = MaterialPath::to_path("-a".into());
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
            let wits = self
                .known_events
                .get_state_at_event(&to_forward)?
                .witness_config
                .witnesses;
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
