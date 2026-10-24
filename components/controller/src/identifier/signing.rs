use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event::sections::seal::EventSeal,
    event_message::{
        cesr_adapter::CesrMessage,
        signature::{signatures_into_groups, Signature, SignerData},
    },
    oobi_manager::storage::OobiStorageBackend,
    prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};
use teliox::database::TelEventDatabase;

use crate::error::ControllerError;

use super::Identifier;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn sign_with_index(
        &self,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<Signature, ControllerError> {
        let last_establishment = self
            .known_events
            .storage
            .get_last_establishment_event_seal(&self.id)
            .ok_or(ControllerError::UnknownIdentifierError)?;
        let sig_data = SignerData::EventSeal(last_establishment);
        let indexes_sig = IndexedSignature::new_both_same(signature, key_index);
        Ok(Signature::Transferable(sig_data, vec![indexes_sig]))
    }

    /// Sign `data` on behalf of `group` — a multi-sig identifier whose
    /// current key set includes one of this device's keys — attributing
    /// the signature to the group's own establishment event at
    /// `key_index`.
    ///
    /// [`Self::sign_to_cesr`] always attributes to `self.id`, which is
    /// right when the alias owns the identifier being spoken for. A
    /// device that participates in a group through its own key is a
    /// different case: it holds a key the group authorises, but the
    /// alias is its own identifier, so a self-attributed signature is
    /// rejected by anyone verifying against the group's key state.
    ///
    /// Registering a group-view alias is the other way to do this, but
    /// that needs the member's seed written to disk; a device whose key
    /// lives in a hardware keystore has no seed to write, and this is
    /// the path left to it.
    pub fn sign_as_group_to_cesr(
        &self,
        data: &str,
        signature: SelfSigningPrefix,
        group: &IdentifierPrefix,
        key_index: u16,
    ) -> Result<String, ControllerError> {
        let group_establishment = self
            .known_events
            .storage
            .get_last_establishment_event_seal(group)
            .ok_or(ControllerError::UnknownIdentifierError)?;
        let signature = Signature::Transferable(
            SignerData::EventSeal(group_establishment),
            vec![IndexedSignature::new_both_same(signature, key_index)],
        );
        CesrMessage {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: signatures_into_groups(&[signature]),
        }
        .to_cesr()
        .map(|data| String::from_utf8(data).unwrap())
        .map_err(|_e| ControllerError::CesrFormatError)
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
        let state = self
            .known_events
            .get_state(&self.id)
            .unwrap()
            .current
            .public_keys;
        let indexed_signatures: Option<Vec<_>> = signatures
            .iter()
            .map(|sig| {
                (
                    sig,
                    (state.iter().position(|bp| match bp.verify(data, sig).ok() {
                        Some(result) => result,
                        None => false,
                    })),
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
        let signature = self.sign_data(data.as_bytes(), signatures)?;
        CesrMessage {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: signatures_into_groups(&[signature]),
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
        let signature = self.sign_with_index(signature, key_index)?;
        CesrMessage {
            payload: cesrox::payload::Payload::JSON(data.into()),
            attachments: signatures_into_groups(&[signature]),
        }
        .to_cesr()
        .map(|data| String::from_utf8(data).unwrap())
        .map_err(|_e| ControllerError::CesrFormatError)
    }

    pub fn verify_from_cesr(&self, stream: &[u8]) -> Result<(), ControllerError> {
        self.known_events.verify_from_cesr(stream)
    }
}
