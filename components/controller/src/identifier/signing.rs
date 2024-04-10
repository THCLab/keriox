use cesrox::ParsedData;
use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::{Signature, SignerData},
    prefix::{IndexedSignature, SelfSigningPrefix},
};

use crate::error::ControllerError;

use super::Identifier;

impl Identifier {
    pub fn sign_with_index(
        &self,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<Signature, ControllerError> {
        let last_establishment = self
            .known_events
            .storage
            .get_last_establishment_event_seal(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        let sig_data = SignerData::EventSeal(last_establishment);
        let indexes_sig = IndexedSignature::new_both_same(signature, key_index);
        Ok(Signature::Transferable(sig_data, vec![indexes_sig]))
    }

    // Returns transferable signature of provided data.
    pub fn sign_data(
        &self,
        data: &[u8],
        signatures: &[SelfSigningPrefix],
    ) -> Result<Signature, ControllerError> {
        let event_seal = self.get_last_establishment_event_seal()?;
        self.transferable_signature(data, event_seal, signatures)
    }

    /// Helper function that produces transferable signature made with
    /// keys corresponding to event in kel that is specified with event_seal. It
    /// computes indexes of provided `SelfSigningIdentifier`s and build `Signature`
    /// from them.
    fn transferable_signature(
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

    // Returns CESR stream of signed data and signatures.
    pub fn sign_to_cesr(
        &self,
        data: &str,
        signatures: &[SelfSigningPrefix],
    ) -> Result<String, ControllerError> {
        // Sign data
        let signature = self.sign_data(data.as_bytes(), signatures)?;
        ParsedData {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: vec![signature.into()],
        }
        .to_cesr()
        .map(|data| String::from_utf8(data).unwrap())
        .map_err(|_e| ControllerError::CesrFormatError)
    }

    pub fn sign_with_index_to_cesr(
        &self,
        data: &str,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<String, ControllerError> {
        // Sign data
        let signature = self.sign_with_index(signature, key_index)?;
        ParsedData {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: vec![signature.into()],
        }
        .to_cesr()
        .map(|data| String::from_utf8(data).unwrap())
        .map_err(|_e| ControllerError::CesrFormatError)
    }
}
