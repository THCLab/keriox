use cesrox::{parse_many, payload::Payload, ParsedData};
use itertools::Itertools;
use keri_core::{
    error::Error,
    event_message::signature::{get_signatures, Signature},
    oobi::Oobi,
    processor::validator::{EventValidator, VerificationError},
};
use thiserror::Error;

use crate::{error::ControllerError, known_events::KnownEvents};


impl KnownEvents {
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), VerificationError> {
        let verifier = EventValidator::new(self.storage.db.clone());
        verifier.verify(data, signature)
    }

    /// Parse elements from CESR stream and splits them into OOBIs to be
    /// resolved and signed credentials.
    fn _parse_cesr_stream(
        &self,
        stream: &str,
    ) -> Result<(Vec<Oobi>, Vec<ParsedData>), ControllerError> {
        let (_rest, data) =
            parse_many(stream.as_bytes()).map_err(|_e| ControllerError::CesrFormatError)?;
        // Split into OOBIs and other data
        let (oobis, to_verify): (Vec<Oobi>, Vec<_>) = data.into_iter().partition_map(|d| {
            let oobi: Result<Oobi, _> = match &d.payload {
                Payload::JSON(json) => serde_json::from_slice(json)
                    .map_err(|_e| ControllerError::OtherError("Wrong JSON".to_string())),
                Payload::CBOR(_) => Err(ControllerError::OtherError(
                    "CBOR format not implemented yet".to_string(),
                )),
                Payload::MGPK(_) => Err(ControllerError::OtherError(
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

    fn verify_from_cesr(&self, stream: &str) -> Result<(), ControllerError> {
        let (_rest, data) =
            parse_many(stream.as_bytes()).map_err(|_e| ControllerError::CesrFormatError)?;
        self.verify_parsed(&data)
    }

    /// Verify signed data that was parsed from cesr stream.
    fn verify_parsed(&self, data: &[ParsedData]) -> Result<(), ControllerError> {
        let mut err_reasons: Vec<VerificationError> = vec![];
        let (_oks, errs): (Vec<_>, Vec<_>) = data.iter().partition(|d| {
            match d
                .attachments
                .iter()
                .flat_map(|a| get_signatures(a.clone()).unwrap())
                .try_for_each(|s| {
                    let payload = match &d.payload {
                        Payload::JSON(json) => json,
                        Payload::CBOR(cbor) => cbor,
                        Payload::MGPK(mgpk) => mgpk,
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
