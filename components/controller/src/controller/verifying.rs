use itertools::Itertools;
use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event::sections::seal::EventSeal,
    event_message::{
        cesr_adapter::{parse_cesr_stream_many, CesrMessage},
        signature::{Signature, SignerData},
    },
    oobi::Oobi,
    oobi_manager::storage::OobiStorageBackend,
    processor::validator::{EventValidator, VerificationError},
};
use said::SelfAddressingIdentifier;
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
            let signatures = collect_signatures(attachments);
            let payload = match &d.payload {
                cesrox::payload::Payload::JSON(json) => json,
                cesrox::payload::Payload::CBOR(cbor) => cbor,
                cesrox::payload::Payload::MGPK(mgpk) => mgpk,
            };
            match signatures
                .into_iter()
                .try_for_each(|s| self.verify(payload, &s))
            {
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

fn collect_signatures(attachments: &[cesrox::group::Group]) -> Vec<Signature> {
    use cesrox::group::Group;
    use keri_core::event_message::signature::Nontransferable;

    let mut signatures = Vec::new();
    let mut i = 0;
    while i < attachments.len() {
        match &attachments[i] {
            Group::AnchoringSeals(seals) => {
                if let Some(seal) = seals.first() {
                    let seal = EventSeal::new(
                        seal.0.clone().into(),
                        seal.1,
                        SelfAddressingIdentifier::from(seal.2.clone()),
                    );
                    i += 1;
                    let indexed_sigs = if i < attachments.len() {
                        if let Group::IndexedControllerSignatures(sigs) = &attachments[i] {
                            sigs.iter().map(|s| s.clone().into()).collect()
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
                let indexed_sigs: Vec<_> = sigs.iter().map(|s| s.clone().into()).collect();
                signatures.push(Signature::Transferable(
                    SignerData::JustSignatures,
                    indexed_sigs,
                ));
                i += 1;
            }
            Group::NontransReceiptCouples(couplets) => {
                let couples: Vec<_> = couplets
                    .iter()
                    .map(|(bp, sp)| (bp.clone().into(), sp.clone().into()))
                    .collect();
                signatures.push(Signature::NonTransferable(Nontransferable::Couplet(
                    couples,
                )));
                i += 1;
            }
            Group::IndexedWitnessSignatures(sigs) => {
                let indexed_sigs: Vec<_> = sigs.iter().map(|s| s.clone().into()).collect();
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
    signatures
}
