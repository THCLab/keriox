//! Structured inspection of raw CESR streams.
//!
//! [`inspect_stream`] parses a CESR stream into its payload(s) and typed
//! attachment summaries so consumers can render human-readable views without
//! importing `cesrox` or matching on low-level group types.

use cesrox::group::Group;
use cesrox::payload::Payload;
use cesrox::value::Value;
use cesrox::primitives::CesrPrimitive;
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
    pub index: Option<u32>,
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
    pub sn: u128,
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
    /// Transferable signatures anchored to a specific KEL event (a `-X`
    /// group: the signer's event seal with its indexed signatures).
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

fn signature_algorithm_name(
    code: &cesrox::primitives::codes::self_signing::SelfSigning,
) -> &'static str {
    use cesrox::primitives::codes::self_signing::SelfSigning;
    match code {
        SelfSigning::Ed25519Sha512 => "Ed25519 signature",
        SelfSigning::ECDSAsecp256k1Sha256 => "ECDSA secp256k1 signature",
        SelfSigning::ECDSA256r1Sha256 => "ECDSA P-256 signature",
        SelfSigning::Ed448 => "Ed448 signature",
        _ => "unknown signature",
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

// The CESR text comes straight from the cesrox primitives, so inspection
// shows every code cesrox parses, including ones keriox does not support.

fn indexed_signature_info(sig: &cesrox::primitives::IndexedSignature) -> SignatureInfo {
    let plain = cesrox::primitives::Signature::new(sig.code.code, sig.raw.clone());
    SignatureInfo {
        index: Some(sig.code.index.current()),
        cesr: plain.to_str(),
        algorithm: signature_algorithm_name(&sig.code.code).to_string(),
    }
}

fn plain_signature_info(sig: &cesrox::primitives::Signature) -> SignatureInfo {
    SignatureInfo {
        index: None,
        cesr: sig.to_str(),
        algorithm: signature_algorithm_name(&sig.code).to_string(),
    }
}

fn receipt_info(couple: &cesrox::group::NontransReceiptCouple) -> ReceiptInfo {
    ReceiptInfo {
        identifier: couple.key.to_str(),
        signature: plain_signature_info(&couple.signature),
    }
}

fn payload_kind(payload: &Payload) -> Result<PayloadKind> {
    match payload {
        Payload::JSON(_) => Ok(PayloadKind::Json),
        Payload::CBOR(_) => Ok(PayloadKind::Cbor),
        Payload::MGPK(_) => Ok(PayloadKind::Mgpk),
        other => Err(Error::CesrParseError(format!(
            "unsupported payload format: {other:?}"
        ))),
    }
}

/// Convert one run of attachment groups into typed summaries. A `-X` group
/// becomes a single [`AttachmentInfo::TransferableGroups`] entry.
fn convert_groups(groups: &[Group]) -> Vec<AttachmentInfo> {
    let mut out = Vec::new();
    for group in groups {
        match group {
            Group::TransIdxSigGroups(entries) => {
                let sealed = entries
                    .iter()
                    .map(|entry| {
                        let said = SelfAddressingIdentifier::from(entry.digest.clone());
                        SealedSigGroup {
                            identifier: entry.prefix.to_str(),
                            sn: entry.sn,
                            digest: said.to_str(),
                            digest_algorithm: digest_algorithm_name(&HashFunctionCode::from(
                                &said.derivation,
                            ))
                            .to_string(),
                            signatures: entry
                                .signatures
                                .iter()
                                .map(indexed_signature_info)
                                .collect(),
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
                        .map(|group| LastEstSigGroup {
                            identifier: group.prefix.to_str(),
                            signatures: group
                                .signatures
                                .iter()
                                .map(indexed_signature_info)
                                .collect(),
                        })
                        .collect(),
                ));
            }
            other => out.push(AttachmentInfo::Other(other.to_cesr_str())),
        }
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
    let mut parsed = cesrox::values_with(cesr, cesrox::Counting::Quadlets);
    let mut values = Vec::new();
    for value in parsed.by_ref() {
        match value {
            Ok(value) => values.push(value),
            // nothing at the start of the stream is CESR
            Err(e) if values.is_empty() => return Err(Error::CesrParseError(e.to_string())),
            Err(_) => break,
        }
    }
    let rest = parsed.remaining();

    let mut parts: Vec<CesrPart> = Vec::new();
    let mut current_payload: Option<Payload> = None;
    let mut current_groups: Vec<Group> = Vec::new();

    let flush = |payload: Option<Payload>,
                 groups: &mut Vec<Group>,
                 parts: &mut Vec<CesrPart>|
     -> Result<()> {
        if let Some(p) = payload {
            parts.push(CesrPart {
                payload_kind: payload_kind(&p)?,
                payload: p.to_vec(),
                attachments: convert_groups(&std::mem::take(groups)),
            });
        }
        Ok(())
    };

    for value in values {
        match value {
            Value::Payload(p) => {
                flush(current_payload.take(), &mut current_groups, &mut parts)?;
                current_payload = Some(p);
            }
            Value::SpecificGroup(g) => current_groups.push(g),
            Value::UniversalGroup(_code, inner) => {
                for v in inner {
                    match v {
                        Value::Payload(p) => {
                            flush(current_payload.take(), &mut current_groups, &mut parts)?;
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
    flush(current_payload.take(), &mut current_groups, &mut parts)?;

    Ok((parts, rest.to_vec()))
}
