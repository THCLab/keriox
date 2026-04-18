//! High-level signing and verification helpers.
//!
//! These functions hide all CESR encoding details. Consumers never need to
//! import `cesrox`, `IndexedSignature`, or `SelfSigningPrefix` — those are
//! internal implementation details.
//!
//! # Quick start
//!
//! ```no_run
//! use keri_sdk::{signing, Identifier, Signer};
//! use std::sync::Arc;
//!
//! # fn example(id: &Identifier, signer: Arc<Signer>) -> keri_sdk::Result<()> {
//! let envelope = signing::sign(id, &signer, b"hello world")?;
//! println!("CESR: {}", envelope.cesr);
//!
//! let verified = signing::verify(id, envelope.cesr.as_bytes())?;
//! assert_eq!(verified.payload, b"hello world");
//! # Ok(())
//! # }
//! ```

use cesrox::group::Group;
use keri_core::event::sections::seal::EventSeal;
use keri_core::event_message::signature::{get_signatures, Signature, SignerData};
use said::derivation::{HashFunction, HashFunctionCode};
use said::SelfAddressingIdentifier;

use crate::{
    error::{Error, Result},
    identifier::Identifier,
    operations::SigningBackend,
    types::{SignedEnvelope, VerifiedPayload},
};

// CESR `sign_to_cesr` requires a valid JSON payload because the CESR stream
// parser uses serde_json internally. We wrap arbitrary bytes in a minimal
// JSON object `{"p":"...","e":"text"|"b64"}` so the envelope is always
// parseable. The `e` (encoding) field disambiguates text vs. base64 data.

fn wrap_payload(data: &[u8]) -> Result<String> {
    let (p, e): (&str, &str) = if let Ok(s) = std::str::from_utf8(data) {
        (s, "text")
    } else {
        return Ok(serde_json::to_string(&serde_json::json!({
            "p": base64::encode_config(data, base64::URL_SAFE_NO_PAD),
            "e": "b64"
        }))
        .map_err(|e| Error::EncodingError(e.to_string()))?);
    };
    serde_json::to_string(&serde_json::json!({ "p": p, "e": e }))
        .map_err(|e| Error::EncodingError(e.to_string()))
}

fn unwrap_payload(json_bytes: &[u8]) -> Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(json_bytes)
        .map_err(|e| Error::CesrParseError(format!("payload JSON: {e}")))?;
    let p = v
        .get("p")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::CesrParseError("missing 'p' field in payload".into()))?;
    let enc = v.get("e").and_then(|v| v.as_str()).unwrap_or("text");
    match enc {
        "b64" => base64::decode_config(p, base64::URL_SAFE_NO_PAD)
            .map_err(|e| Error::CesrParseError(format!("base64 decode: {e}"))),
        _ => Ok(p.as_bytes().to_vec()),
    }
}

/// Sign arbitrary bytes and return a self-describing CESR envelope.
///
/// The bytes are wrapped in a JSON object (`{"p": "..."}`) so that the CESR
/// stream is always parseable. The signer's current key is used to produce a
/// transferable Ed25519 signature.
///
/// # Errors
/// - [`Error::Signing`] if the signer fails.
/// - [`Error::EncodingError`] if JSON serialisation of the wrapper fails.
/// - [`Error::Controller`] if the CESR envelope cannot be built.
pub fn sign<S: SigningBackend>(
    identifier: &Identifier,
    signer: &S,
    data: &[u8],
) -> Result<SignedEnvelope> {
    let json_payload = wrap_payload(data)?;

    let raw_sig = signer.sign_data(json_payload.as_bytes())?;

    let sig = keri_controller::SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        raw_sig,
    );

    let cesr = identifier.sign_to_cesr(&json_payload, &[sig])?;

    Ok(SignedEnvelope {
        payload: data.to_vec(),
        cesr,
    })
}

/// Sign a UTF-8 string and return a self-describing CESR envelope.
///
/// This is a convenience wrapper around [`sign`] for string payloads such as
/// JSON documents. The string is wrapped in a CESR-compatible JSON envelope
/// before signing, and unwrapped automatically by [`verify`].
///
/// # Errors
/// Same as [`sign`].
pub fn sign_json<S: SigningBackend>(
    identifier: &Identifier,
    signer: &S,
    json: &str,
) -> Result<SignedEnvelope> {
    sign(identifier, signer, json.as_bytes())
}

/// Verify a CESR-signed envelope against the local KEL.
///
/// Parses the CESR stream, verifies every attached signature against the
/// current KEL state of the signer, and returns the payload and signer
/// identifier on success.
///
/// The signer's KEL must already be known locally — call
/// [`Identifier::resolve_oobi`] first if you have not seen this signer before.
///
/// # Errors
/// - [`Error::CesrParseError`] if `cesr` is not a valid CESR stream.
/// - [`Error::VerificationFailed`] if one or more signatures do not verify.
pub fn verify(identifier: &Identifier, cesr: &[u8]) -> Result<VerifiedPayload> {
    identifier
        .verify_from_cesr(cesr)
        .map_err(|e| Error::VerificationFailed(e.to_string()))?;

    let (json_bytes, sigs) = parse_signed_envelope(cesr)?;

    // Unwrap the JSON envelope produced by `sign`.
    let payload = unwrap_payload(&json_bytes)?;

    // Try to extract signer from signature metadata; fall back to the local identifier.
    let signer_id = sigs
        .iter()
        .find_map(|s| s.get_signer())
        .unwrap_or_else(|| identifier.id().clone());

    Ok(VerifiedPayload { payload, signer_id })
}

/// Sign a JSON string and return a CESR stream with the raw JSON as payload.
///
/// Unlike [`sign`] and [`sign_json`], this does **not** wrap the data in a
/// `{"p":"…"}` envelope. The resulting CESR stream contains the exact `json`
/// string as the JSON payload followed by transferable Ed25519 signature
/// attachments.
///
/// This is the format protocols like mesagkesto expect:
/// `<JSON_payload><CESR_signatures>`.
///
/// # Errors
/// - [`Error::Signing`] if the signer fails.
/// - [`Error::Controller`] if the CESR envelope cannot be built.
pub fn sign_to_cesr<S: SigningBackend>(
    identifier: &Identifier,
    signer: &S,
    json: &str,
) -> Result<String> {
    let raw_sig = signer.sign_data(json.as_bytes())?;

    let sig = keri_controller::SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        raw_sig,
    );

    Ok(identifier.sign_to_cesr(json, &[sig])?)
}

/// Parse a CESR stream into raw payload bytes and attached signatures.
///
/// This is a low-level helper for when you need to inspect signature details
/// before deciding whether to verify (e.g. to extract the signer's identifier
/// before calling [`verify`]).
///
/// # Errors
/// - [`Error::CesrParseError`] if `cesr` is not a valid CESR stream.
pub fn parse_signed_envelope(cesr: &[u8]) -> Result<(Vec<u8>, Vec<Signature>)> {
    let parsed = keri_core::event_message::cesr_adapter::parse_cesr_stream(cesr)
        .map_err(|e| Error::CesrParseError(format!("{e:?}")))?;

    let payload = parsed.payload.to_vec();

    let sigs = collect_signatures(&parsed.attachments);

    Ok((payload, sigs))
}

/// Compute a Blake3-256 content hash (SAID) of arbitrary data and return it
/// as a hex string.
///
/// This is the standard hash function used throughout KERI for content
/// addressing. Use it whenever you need a deterministic, collision-resistant
/// digest of a message or payload.
pub fn content_hash(data: &[u8]) -> String {
    let digest: HashFunction = HashFunctionCode::Blake3_256.into();
    digest.derive(data).to_string()
}

/// Compute a Blake3-256 content hash (SAID) and return the typed
/// [`SelfAddressingIdentifier`].
///
/// Use this when you need the SAID as a typed value rather than a string
/// (e.g. for storage keys or response identifiers).
pub fn content_sai(data: &[u8]) -> SelfAddressingIdentifier {
    let digest: HashFunction = HashFunctionCode::Blake3_256.into();
    digest.derive(data)
}

fn collect_signatures(attachments: &[Group]) -> Vec<Signature> {
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
            _ => {
                if let Ok(sigs) = get_signatures(attachments[i].clone()) {
                    signatures.extend(sigs);
                }
                i += 1;
            }
        }
    }
    signatures
}

/// Sign data with a non-transferable (basic) key and produce a CESR stream.
///
/// The resulting bytes are `payload || CESR-attachment` where the attachment
/// is a `NontransReceiptCouples` group containing the signer's public key
/// and Ed25519 signature.
///
/// This is the format expected by services like mesagkesto for
/// authenticating requests.
pub fn sign_nontransferable(
    public_key: &keri_controller::BasicPrefix,
    signer: &keri_core::signer::Signer,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let raw_sig = signer
        .sign(payload)
        .map_err(|e| Error::Signing(e.to_string()))?;

    let sig = keri_controller::SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        raw_sig,
    );

    let group =
        cesrox::group::Group::NontransReceiptCouples(vec![(public_key.clone().into(), sig.into())]);

    let mut stream = payload.to_vec();
    stream.extend_from_slice(group.to_cesr_str().as_bytes());
    Ok(stream)
}
