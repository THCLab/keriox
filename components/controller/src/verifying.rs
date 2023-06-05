use cesrox::{parse_many, payload::Payload, ParsedData};
use keri::{
    error::Error,
    event_message::signature::{get_signatures, Signature},
    processor::validator::EventValidator,
};

use crate::{error::ControllerError, Controller};

impl Controller {
    /// Parse elements from cesr stream and splits them into oobis to be
    /// resolved and signed credentials.
    pub fn parse_cesr_stream(
        &self,
        stream: &str,
    ) -> Result<(Vec<String>, Vec<ParsedData>), ControllerError> {
        let (_rest, data) =
            parse_many(stream.as_bytes()).map_err(|_e| ControllerError::CesrFormatError)?;
        // When attachments are empty, it is expected to be an oobi.
        let (oobis, to_verify): (Vec<_>, Vec<_>) =
            data.into_iter().partition(|d| d.attachments.is_empty());
        let oo: Result<Vec<_>, ControllerError> = oobis
            .into_iter()
            .map(|o| match o.payload {
                Payload::JSON(json_oobi) => {
                    String::from_utf8(json_oobi).map_err(|_e| ControllerError::WrongEventTypeError)
                }
                Payload::CBOR(_) => Err(ControllerError::OtherError(
                    "CBOR format not implemented yet".to_string(),
                )),
                Payload::MGPK(_) => Err(ControllerError::OtherError(
                    "MGPK format not implemented yet".to_string(),
                )),
            })
            .collect();
        Ok((oo?, to_verify))
    }

    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<(), ControllerError> {
        let verifier = EventValidator::new(self.storage.db.clone());
        verifier.verify(data, signature).map_err(|e| match e {
            Error::SignatureVerificationError | Error::FaultySignatureVerification => {
                ControllerError::FaultySignature
            }
            Error::MissingSigner => ControllerError::UnknownIdentifierError,
            Error::EventOutOfOrderError => ControllerError::MissingEventError,
            e => ControllerError::OtherError(e.to_string()),
        })
    }

    pub fn verify_from_cesr(&self, stream: &str) -> Result<(), ControllerError> {
        let (_rest, data) =
            parse_many(stream.as_bytes()).map_err(|_e| ControllerError::CesrFormatError)?;
        self.verify_parsed(&data)
    }

    /// Verify signed data that was parsed from cesr stream.
    pub fn verify_parsed(&self, data: &[ParsedData]) -> Result<(), ControllerError> {
        let mut err_reasons: Vec<ControllerError> = vec![];
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
