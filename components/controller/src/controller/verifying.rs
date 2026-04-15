use itertools::Itertools;
use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event_message::{
        cesr_adapter::{parse_cesr_stream_many, CesrMessage},
        signature::{get_signatures, Signature},
    },
    oobi::Oobi,
    oobi_manager::storage::OobiStorageBackend,
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
            match d
                .attachments
                .iter()
                .flat_map(|a| get_signatures(a.clone()).unwrap())
                .try_for_each(|s| {
                    let payload = match &d.payload {
                        cesrox::payload::Payload::JSON(json) => json,
                        cesrox::payload::Payload::CBOR(cbor) => cbor,
                        cesrox::payload::Payload::MGPK(mgpk) => mgpk,
                    };
                    self.verify(payload, &s)
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
