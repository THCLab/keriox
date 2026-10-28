use itertools::Itertools;
use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event::sections::seal::EventSeal,
    event_message::{
        cesr_adapter::{indexed_signatures, parse_cesr_stream_many, receipt_couples, CesrMessage},
        signature::{Signature, SignerData},
    },
    oobi::Oobi,
    oobi_manager::storage::OobiStorageBackend,
    processor::validator::{EventValidator, VerificationError},
};
use teliox::registry::RegistryStore;

use crate::{error::ControllerError, known_events::KnownEvents};

impl<D, T, S> KnownEvents<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
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
        // A stream with nothing in it vouches for nothing.
        if data.is_empty() {
            return Err(ControllerError::CesrFormatError);
        }
        let mut err_reasons: Vec<VerificationError> = vec![];
        let (_oks, errs): (Vec<_>, Vec<_>) = data.iter().partition(|d| {
            let attachments = &d.attachments;
            let payload = d.payload.to_vec();
            match collect_signatures(attachments).and_then(|signatures| {
                // Every message needs at least one signature that verifies.
                if signatures.is_empty() {
                    return Err(VerificationError::MissingSignatures);
                }
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
    use keri_core::event_message::signature::{get_signatures, Nontransferable};

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
            Group::TransIdxSigGroups(_) => {
                signatures.extend(
                    get_signatures(attachments[i].clone())
                        .map_err(|_| VerificationError::VerificationFailure)?,
                );
                i += 1;
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
                let couples = receipt_couples(couplets.iter().cloned())
                    .map_err(|_| VerificationError::VerificationFailure)?;
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

#[cfg(test)]
mod test {
    use keri_core::{
        prefix::{BasicPrefix, SelfSigningPrefix},
        signer::{CryptoBox, KeyManager},
    };
    use tempfile::{Builder, TempDir};

    use crate::{
        config::ControllerConfig,
        controller::{Controller, RedbIdentifier},
    };

    struct Signer {
        identifier: RedbIdentifier,
        keys: CryptoBox,
        _db: TempDir,
    }

    impl Signer {
        fn sign_to_cesr(&self, data: &str) -> String {
            let sig = SelfSigningPrefix::Ed25519Sha512(self.keys.sign(data.as_bytes()).unwrap());
            self.identifier.sign_to_cesr(data, &[sig]).unwrap()
        }
    }

    async fn signer() -> Signer {
        let db = Builder::new().prefix("verify-cesr").tempdir().unwrap();
        let controller = Controller::new(ControllerConfig {
            db_path: db.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        let keys = CryptoBox::new().unwrap();
        let icp = controller
            .incept(
                vec![BasicPrefix::Ed25519(keys.public_key())],
                vec![BasicPrefix::Ed25519(keys.next_public_key())],
                vec![],
                0,
            )
            .await
            .unwrap();
        let sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes()).unwrap());
        let identifier = controller.finalize_incept(icp.as_bytes(), &sig).unwrap();
        Signer {
            identifier,
            keys,
            _db: db,
        }
    }

    #[async_std::test]
    async fn a_signed_json_payload_verifies() {
        let signer = signer().await;
        let stream = signer.sign_to_cesr(r#"{"msg":"hello"}"#);

        let result = signer.identifier.verify_from_cesr(stream.as_bytes());

        assert!(result.is_ok(), "expected success, got {result:?}");
    }

    #[async_std::test]
    async fn a_json_payload_without_signatures_does_not_verify() {
        let signer = signer().await;

        let result = signer.identifier.verify_from_cesr(br#"{"msg":"hello"}"#);

        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    #[async_std::test]
    async fn a_signed_payload_that_is_not_json_does_not_verify() {
        let signer = signer().await;
        let stream = signer.sign_to_cesr("hello");

        let result = signer.identifier.verify_from_cesr(stream.as_bytes());

        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    #[async_std::test]
    async fn an_empty_stream_does_not_verify() {
        let signer = signer().await;

        let result = signer.identifier.verify_from_cesr(b"");

        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    #[async_std::test]
    async fn a_json_payload_with_an_empty_signature_group_does_not_verify() {
        let signer = signer().await;

        let result = signer
            .identifier
            .verify_from_cesr(br#"{"msg":"hello"}-CAA"#);

        assert!(result.is_err(), "expected an error, got {result:?}");
    }

    #[async_std::test]
    async fn a_signature_moved_onto_another_payload_does_not_verify() {
        let signer = signer().await;
        let signed = signer.sign_to_cesr("hello");
        let swapped = signed.replacen("hello", "bye!!", 1);

        let result = signer.identifier.verify_from_cesr(swapped.as_bytes());

        assert!(result.is_err(), "expected an error, got {result:?}");
    }
}
