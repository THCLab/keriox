use cesrox::{group::Group, ParsedData};
use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::{Signature, SignerData},
    prefix::{IndexedSignature, SelfSigningPrefix},
};

use crate::error::ControllerError;

use super::Identifier;

impl Identifier {
    pub fn sign(
        &self,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<Signature, ControllerError> {
        let last_establishment = self
            .known_events
            .storage
            .get_last_establishment_event_seal(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        let sig_data = SignerData::EventSeal(EventSeal {
            prefix: self.id.clone(),
            sn: last_establishment.sn,
            event_digest: last_establishment.event_digest,
        });
        let indexes_sig = IndexedSignature::new_both_same(signature, key_index);
        Ok(Signature::Transferable(sig_data, vec![indexes_sig]))
    }

    /// Helper function that produces transferable signature made with
    /// keys corresponding to event in kel that is specified with event_seal. It
    /// computes indexes of provided `SelfSigningIdentifier`s and build `Signature`
    /// from them.
    pub fn transferable_signature(
        &self,
        data: &[u8],
        event_seal: EventSeal,
        signatures: &[SelfSigningPrefix],
    ) -> Result<Signature, ControllerError> {
        let state = self.known_events.get_state(&self.id)?.current.public_keys;
        let indexed_signatures: Option<Vec<_>> = signatures
            .iter()
            .map(|sig| {
                (
                    sig,
                    (state
                        .iter()
                        .position(|bp| bp.verify(data, sig).ok().is_some())),
                )
            })
            .map(|(sig, index)| {
                index.map(|i| IndexedSignature::new_both_same(sig.clone(), i as u16))
            })
            .collect();
        let signature = Signature::Transferable(
            SignerData::EventSeal(event_seal),
            indexed_signatures.expect("Provided signatures do not match any of the keys corresponding to the provided event seal"),
        );
        Ok(signature)
    }

    pub fn to_cesr_signature(
        &self,
        sig: SelfSigningPrefix,
        index: u16,
    ) -> Result<String, ControllerError> {
        let signature: Signature = self.sign(sig, index)?;
        let group: Group = signature.into();
        Ok(group.to_cesr_str())
    }

    pub fn sign_to_cesr(
        &self,
        data: &str,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<String, ControllerError> {
        // Sign attestation
        let signature = self.sign(signature, key_index)?;
        ParsedData {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: vec![signature.into()],
        }
        .to_cesr()
        .map(|data| String::from_utf8(data).unwrap())
        .map_err(|_e| ControllerError::CesrFormatError)
    }
}
