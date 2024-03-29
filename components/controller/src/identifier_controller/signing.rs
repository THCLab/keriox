use cesrox::{group::Group, ParsedData};
use keri_core::{
    event::sections::seal::EventSeal,
    event_message::signature::{Signature, SignerData},
    prefix::{IndexedSignature, SelfSigningPrefix},
};

use crate::error::ControllerError;

use super::IdentifierController;

impl IdentifierController {
    pub fn sign(
        &self,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<Signature, ControllerError> {
        let last_establishment = self
            .source
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
