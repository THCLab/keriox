//! Structured inspection of raw CESR streams.
//!
//! [`inspect_stream`] parses a CESR stream into its payload(s) and typed
//! attachment summaries so consumers can render human-readable views without
//! importing `cesrox` or matching on low-level group types.

use cesrox::group::Group;
use cesrox::payload::Payload;
use cesrox::value::Value;
use keri_controller::{BasicPrefix, SelfSigningPrefix};
use keri_core::prefix::CesrPrimitive;
use said::derivation::HashFunctionCode;
use said::SelfAddressingIdentifier;

use crate::advanced::error::{Error, Result};

/// Serialization format of a CESR payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadKind {
    Json,
    Cbor,
    Mgpk,
}

/// A single signature found in a CESR attachment.
#[derive(Debug, Clone)]
pub struct SignatureInfo {
    /// Signing key index within the controller's current key set, when indexed.
    pub index: Option<u16>,
    /// The CESR text form of the signature.
    pub cesr: String,
    /// Human-readable signature algorithm name.
    pub algorithm: String,
}

/// A non-transferable receipt couple: signer public key + signature.
#[derive(Debug, Clone)]
pub struct ReceiptInfo {
    /// CESR text form of the signer's public key prefix.
    pub identifier: String,
    pub signature: SignatureInfo,
}

/// A transferable signature group anchored to a KEL event.
#[derive(Debug, Clone)]
pub struct SealedSigGroup {
    /// CESR text form of the signer's identifier prefix.
    pub identifier: String,
    /// Sequence number of the anchoring KEL event.
    pub sn: u64,
    /// CESR text form of the anchoring event digest.
    pub digest: String,
    /// Human-readable digest algorithm name.
    pub digest_algorithm: String,
    pub signatures: Vec<SignatureInfo>,
}

/// A transferable signature group bound to the signer's last establishment event.
#[derive(Debug, Clone)]
pub struct LastEstSigGroup {
    /// CESR text form of the signer's identifier prefix.
    pub identifier: String,
    pub signatures: Vec<SignatureInfo>,
}

/// A typed summary of one CESR attachment group.
#[derive(Debug, Clone)]
pub enum AttachmentInfo {
    /// Indexed controller signatures.
    ControllerSignatures(Vec<SignatureInfo>),
    /// Indexed witness signatures.
    WitnessSignatures(Vec<SignatureInfo>),
    /// Non-transferable receipt couples.
    NonTransferableReceipts(Vec<ReceiptInfo>),
    /// Transferable signatures anchored to a specific KEL event
    /// (an anchoring seal followed by indexed controller signatures).
    TransferableGroups(Vec<SealedSigGroup>),
    /// Transferable signatures bound to the signer's last establishment event.
    LastEstablishmentGroups(Vec<LastEstSigGroup>),
    /// Any other group, rendered as its raw CESR text.
    Other(String),
}

/// One payload with the attachments that follow it in the stream.
#[derive(Debug, Clone)]
pub struct CesrPart {
    /// Raw payload bytes (JSON / CBOR / MGPK document).
    pub payload: Vec<u8>,
    pub payload_kind: PayloadKind,
    pub attachments: Vec<AttachmentInfo>,
}

fn signature_algorithm_name(code: &cesrox::primitives::codes::self_signing::SelfSigning) -> &'static str {
    use cesrox::primitives::codes::self_signing::SelfSigning;
    match code {
        SelfSigning::Ed25519Sha512 => "Ed25519 signature",
        SelfSigning::ECDSAsecp256k1Sha256 => "ECDSA secp256k1 signature",
        SelfSigning::ECDSA256r1Sha256 => "ECDSA P-256 signature",
        SelfSigning::Ed448 => "Ed448 signature",
    }
}

fn digest_algorithm_name(code: &HashFunctionCode) -> &'static str {
    match code {
        HashFunctionCode::Blake3_256 => "Blake3-256 Digest",
        HashFunctionCode::Blake2B256 => "Blake2b-256 Digest",
        HashFunctionCode::Blake2S256 => "Blake2s-256 Digest",
        HashFunctionCode::SHA3_256 => "SHA3-256 Digest",
        HashFunctionCode::SHA2_256 => "SHA2-256 Digest",
        HashFunctionCode::Blake3_512 => "Blake3-512 Digest",
        HashFunctionCode::SHA3_512 => "SHA3-512 Digest",
        HashFunctionCode::Blake2B512 => "Blake2b-512 Digest",
        HashFunctionCode::SHA2_512 => "SHA2-512 Digest",
    }
}

fn indexed_signature_info(sig: &cesrox::primitives::IndexedSignature) -> SignatureInfo {
    let (code, bytes) = sig;
    let prefix = SelfSigningPrefix::new(code.code, bytes.clone());
    SignatureInfo {
        index: Some(code.index.current()),
        cesr: prefix.to_str(),
        algorithm: signature_algorithm_name(&code.code).to_string(),
    }
}

fn plain_signature_info(sig: &cesrox::primitives::Signature) -> SignatureInfo {
    let (code, bytes) = sig;
    let prefix = SelfSigningPrefix::new(*code, bytes.clone());
    SignatureInfo {
        index: None,
        cesr: prefix.to_str(),
        algorithm: signature_algorithm_name(code).to_string(),
    }
}

fn receipt_info(pair: &(cesrox::primitives::PublicKey, cesrox::primitives::Signature)) -> ReceiptInfo {
    let ((basic_code, key_bytes), signature) = pair;
    let identifier = BasicPrefix::new(
        *basic_code,
        keri_core::keys::PublicKey {
            public_key: key_bytes.clone(),
        },
    )
    .to_str();
    ReceiptInfo {
        identifier,
        signature: plain_signature_info(signature),
    }
}

fn payload_kind(payload: &Payload) -> PayloadKind {
    match payload {
        Payload::JSON(_) => PayloadKind::Json,
        Payload::CBOR(_) => PayloadKind::Cbor,
        Payload::MGPK(_) => PayloadKind::Mgpk,
    }
}

/// Convert one run of attachment groups into typed summaries. Anchoring
/// seals followed by indexed controller signatures are merged into a single
/// [`AttachmentInfo::TransferableGroups`] entry, matching how transferable
/// signatures are encoded on the wire.
fn convert_groups(groups: &[Group]) -> Vec<AttachmentInfo> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < groups.len() {
        match &groups[i] {
            Group::AnchoringSeals(seals) => {
                let signatures = if let Some(Group::IndexedControllerSignatures(sigs)) =
                    groups.get(i + 1)
                {
                    i += 1;
                    sigs.iter().map(indexed_signature_info).collect()
                } else {
                    vec![]
                };
                let sealed = seals
                    .iter()
                    .map(|(identifier, sn, digest)| {
                        let said = SelfAddressingIdentifier::from(digest.clone());
                        let identifier: keri_controller::IdentifierPrefix =
                            identifier.clone().into();
                        let identifier = identifier.to_str();
                        SealedSigGroup {
                            identifier,
                            sn: *sn,
                            digest: said.to_str(),
                            digest_algorithm: digest_algorithm_name(&HashFunctionCode::from(
                                &said.derivation,
                            ))
                            .to_string(),
                            signatures: signatures.clone(),
                        }
                    })
                    .collect();
                out.push(AttachmentInfo::TransferableGroups(sealed));
            }
            Group::IndexedControllerSignatures(sigs) => {
                out.push(AttachmentInfo::ControllerSignatures(
                    sigs.iter().map(indexed_signature_info).collect(),
                ));
            }
            Group::IndexedWitnessSignatures(sigs) => {
                out.push(AttachmentInfo::WitnessSignatures(
                    sigs.iter().map(indexed_signature_info).collect(),
                ));
            }
            Group::NontransReceiptCouples(couples) => {
                out.push(AttachmentInfo::NonTransferableReceipts(
                    couples.iter().map(receipt_info).collect(),
                ));
            }
            Group::TransLastIdxSigGroups(groups) => {
                out.push(AttachmentInfo::LastEstablishmentGroups(
                    groups
                        .iter()
                        .map(|(identifier, sigs)| {
                            let identifier: keri_controller::IdentifierPrefix =
                                identifier.clone().into();
                            LastEstSigGroup {
                                identifier: identifier.to_str(),
                                signatures: sigs.iter().map(indexed_signature_info).collect(),
                            }
                        })
                        .collect(),
                ));
            }
            other => out.push(AttachmentInfo::Other(other.to_cesr_str())),
        }
        i += 1;
    }
    out
}

/// Parse a CESR stream into typed payload + attachment summaries.
///
/// Returns the parsed parts and any unparsed trailing bytes. Whitespace is
/// NOT stripped — callers that accept hand-edited input should remove
/// whitespace first.
///
/// # Errors
/// - [`Error::CesrParseError`] if the stream is not valid CESR.
pub fn inspect_stream(cesr: &[u8]) -> Result<(Vec<CesrPart>, Vec<u8>)> {
    let text =
        std::str::from_utf8(cesr).map_err(|e| Error::CesrParseError(format!("not UTF-8: {e}")))?;
    let (rest, values) =
        cesrox::parse_all(text).map_err(|e| Error::CesrParseError(e.to_string()))?;

    let mut parts: Vec<CesrPart> = Vec::new();
    let mut current_payload: Option<Payload> = None;
    let mut current_groups: Vec<Group> = Vec::new();

    let flush = |payload: Option<Payload>, groups: &mut Vec<Group>, parts: &mut Vec<CesrPart>| {
        if let Some(p) = payload {
            parts.push(CesrPart {
                payload_kind: payload_kind(&p),
                payload: p.to_vec(),
                attachments: convert_groups(&std::mem::take(groups)),
            });
        }
    };

    for value in values {
        match value {
            Value::Payload(p) => {
                flush(current_payload.take(), &mut current_groups, &mut parts);
                current_payload = Some(p);
            }
            Value::SpecificGroup(g) => current_groups.push(g),
            Value::UniversalGroup(_code, inner) => {
                for v in inner {
                    match v {
                        Value::Payload(p) => {
                            flush(current_payload.take(), &mut current_groups, &mut parts);
                            current_payload = Some(p);
                        }
                        Value::SpecificGroup(g) => current_groups.push(g),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    flush(current_payload.take(), &mut current_groups, &mut parts);

    Ok((parts, rest.as_bytes().to_vec()))
}
