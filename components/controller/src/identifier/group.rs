use keri_core::{actor::{event_generator, MaterialPath}, event::sections::threshold::SignatureThreshold, event_message::{cesr_adapter::{parse_event_type, EventType}, signature::{Signature, SignerData}, signed_event_message::{Message, Op}}, mailbox::exchange::{Exchange, ForwardTopic, SignedExchange}, prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix}};

use crate::error::ControllerError;

use super::Identifier;


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
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<IdentifierPrefix>,
    ) -> Result<(String, Vec<String>), ControllerError> {
        let key_config = self
            .known_events
            .storage
            .get_state(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)?
            .current;

        let mut pks = key_config.public_keys;
        let mut npks = key_config.next_keys_data.next_key_hashes;
        for participant in &participants {
            let state = self
                .known_events
                .storage
                .get_state(participant)?
                .ok_or(ControllerError::UnknownIdentifierError)?;
            pks.append(&mut state.clone().current.public_keys);
            npks.append(&mut state.clone().current.next_keys_data.next_key_hashes);
        }

        let icp = event_generator::incept_with_next_hashes(
            pks,
            &SignatureThreshold::Simple(signature_threshold),
            npks,
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
            delegator.as_ref(),
        )?;

        let serialized_icp = String::from_utf8(icp.encode()?)
            .map_err(|e| ControllerError::EventGenerationError(e.to_string()))?;

        let mut exchanges = participants
            .iter()
            .map(|id| -> Result<_, _> {
                let exn = event_generator::exchange(id, &icp, ForwardTopic::Multisig)?.encode()?;
                String::from_utf8(exn).map_err(|_e| ControllerError::EventFormatError)
            })
            .collect::<Result<Vec<String>, ControllerError>>()?;

        if let Some(delegator) = delegator {
            let delegation_request = String::from_utf8(
                event_generator::exchange(&delegator, &icp, ForwardTopic::Delegate)?.encode()?,
            )
            .map_err(|_e| ControllerError::EventFormatError)?;
            exchanges.push(delegation_request);
        }

        Ok((serialized_icp, exchanges))
    }

	/// Finalizes group identifier.
    /// Joins event with signature and verifies them.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function
    /// to send signed exn messages to witness to be forwarded to group participants.
    pub async fn finalize_group_incept(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, SelfSigningPrefix)>,
    ) -> Result<IdentifierPrefix, ControllerError> {
        // Join icp event with signature
        let key_event =
            parse_event_type(group_event).map_err(|_e| ControllerError::EventFormatError)?;
        let ke = if let EventType::KeyEvent(icp) = key_event {
            icp
        } else {
            return Err(ControllerError::WrongEventTypeError);
        };
        let own_index = self.get_index(&ke.data)?;
        let group_prefix = ke.data.get_prefix();

        self.known_events.finalize_key_event(&ke, &sig, own_index)?;

        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = ke.sign(vec![signature], None, None);
        self.to_notify.push(signed_message);

        let att_signature = IndexedSignature::new_both_same(sig, own_index as u16);

        for (exn, signature) in exchanges {
            self.finalize_exchange(&exn, signature, att_signature.clone())
                .await?;
        }
        Ok(group_prefix)
    }

	pub async fn finalize_exchange(
        &self,
        exchange: &[u8],
        exn_signature: SelfSigningPrefix,
        data_signature: IndexedSignature,
    ) -> Result<(), ControllerError> {
        // Join exn messages with their signatures and send it to witness.
        let material_path = MaterialPath::to_path("-a".into());
        // let attached_sig = sigs;
        let parsed_exn =
            parse_event_type(exchange).map_err(|_e| ControllerError::EventFormatError)?;
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

            let signature = vec![Signature::Transferable(
                SignerData::LastEstablishment(self.id.clone()),
                vec![IndexedSignature::new_both_same(
                    exn_signature,
                    // TODO
                    0,
                )],
            )];
            let signer_exn = Message::Op(Op::Exchange(SignedExchange {
                exchange_message: exn,
                signature,
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
                        &IdentifierPrefix::Basic(wit.clone()),
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