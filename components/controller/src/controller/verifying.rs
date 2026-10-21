use itertools::Itertools;
use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event::sections::seal::EventSeal,
    event_message::{
        cesr_adapter::{indexed_signatures, parse_cesr_stream_many, CesrMessage},
        signature::{Signature, SignerData},
    },
    oobi::Oobi,
    oobi_manager::storage::OobiStorageBackend,
    prefix::cesr_adapter::from_receipt_couple,
    processor::validator::{EventValidator, VerificationError},
};
use teliox::database::TelEventDatabase;

use crate::{error::ControllerError, known_events::KnownEvents};

impl<D, T, S> KnownEvents<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), VerificationError> {
        let verifier = EventValidator::new(self.storage.events_db.clone());
        verifier.verify(data, signature)
    }

    fn _parse_cesr_stream(
        &self,
        stream: &str,
    ) -> Result<(Vec<Oobi>, Vec<CesrMessage>), ControllerError> {
        let data = parse_cesr_stream_many(stream.as_bytes())
            .map_err(|_e| ControllerError::CesrFormatError)?;
        let (oobis, to_verify): (Vec<Oobi>, Vec<_>) = data.into_iter().partition_map(|d| {
            let oobi: Result<Oobi, _> = match &d.payload {
                cesrox::payload::Payload::JSON(json) => serde_json::from_slice(json)
                    .map_err(|_e| ControllerError::OtherError("Wrong JSON".to_string())),
                cesrox::payload::Payload::CBOR(_) => Err(ControllerError::OtherError(
                    "CBOR format not implemented yet".to_string(),
                )),
                cesrox::payload::Payload::MGPK(_) => Err(ControllerError::OtherError(
                    "MGPK format not implemented yet".to_string(),
                )),
                _ => Err(ControllerError::OtherError(
                    "Unsupported payload format".to_string(),
                )),
            };
            match oobi {
                Ok(oobi) => itertools::Either::Left(oobi),
                Err(_) => itertools::Either::Right(d),
            }
        });

        Ok((oobis, to_verify))
    }

    pub fn verify_from_cesr(&self, stream: &[u8]) -> Result<(), ControllerError> {
        let data = parse_cesr_stream_many(stream).map_err(|_e| ControllerError::CesrFormatError)?;
        self.verify_parsed(&data)
    }

    fn verify_parsed(&self, data: &[CesrMessage]) -> Result<(), ControllerError> {
        let mut err_reasons: Vec<VerificationError> = vec![];
        let (_oks, errs): (Vec<_>, Vec<_>) = data.iter().partition(|d| {
            let attachments = &d.attachments;
            let payload = d.payload.to_vec();
            match collect_signatures(attachments).and_then(|signatures| {
                signatures
                    .into_iter()
                    .try_for_each(|s| self.verify(&payload, &s))
            }) {
                Ok(_) => true,
                Err(err) => {
                    err_reasons.push(err);
                    false
                }
            }
        });
        if errs.is_empty() {
            Ok(())
        } else {
            let err = err_reasons.into_iter().zip(
                errs.iter()
                    .map(|d| String::from_utf8(d.to_cesr().unwrap()).unwrap()),
            );
            Err(ControllerError::VerificationError(err.collect()))
        }
    }
}

/// Signatures in `attachments`. Signatures that cannot be read, such as ones
/// with an out-of-range index, fail verification.
fn collect_signatures(
    attachments: &[cesrox::group::Group],
) -> Result<Vec<Signature>, VerificationError> {
    use cesrox::group::Group;
    use keri_core::event_message::signature::Nontransferable;

    let mut signatures = Vec::new();
    let mut i = 0;
    while i < attachments.len() {
        match &attachments[i] {
            Group::AnchoringSeals(seals) => {
                if let Some(seal) = seals.first() {
                    let seal = EventSeal::try_from(seal.clone())
                        .map_err(|_| VerificationError::VerificationFailure)?;
                    i += 1;
                    let indexed_sigs = if i < attachments.len() {
                        if let Group::IndexedControllerSignatures(sigs) = &attachments[i] {
                            indexed_signatures(sigs.iter().cloned())
                                .map_err(|_| VerificationError::VerificationFailure)?
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };
                    if !indexed_sigs.is_empty() {
                        i += 1;
                    }
                    signatures.push(Signature::Transferable(
                        SignerData::EventSeal(seal),
                        indexed_sigs,
                    ));
                } else {
                    i += 1;
                }
            }
            Group::IndexedControllerSignatures(sigs) => {
                let indexed_sigs = indexed_signatures(sigs.iter().cloned())
                    .map_err(|_| VerificationError::VerificationFailure)?;
                signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
                i += 1;
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples = couplets.iter().cloned().map(from_receipt_couple).collect();
                signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
                i += 1;
            }
            Group::IndexedWitnessSignatures(sigs) => {
                let indexed_sigs = indexed_signatures(sigs.iter().cloned())
                    .map_err(|_| VerificationError::VerificationFailure)?;
                signatures.push(Signature::NonTransferable(Nontransferable::Indexed(
                    indexed_sigs,
                )));
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    Ok(signatures)
}
