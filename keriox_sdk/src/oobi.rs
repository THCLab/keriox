//! OOBI helpers for common operations.
//!
//! These functions hide the OOBI type discrimination (Location vs EndRole)
//! and CESR reply stream serialization from application code.

use cesrox::payload::Payload;
use keri_core::event_message::{
    cesr_adapter::parse_cesr_stream_many,
    signed_event_message::{Message, Op},
};
use keri_core::query::reply_event::{ReplyEvent, ReplyRoute, SignedReply};
use said::derivation::HashFunctionCode;
use said::sad::SerializationFormats;

use crate::error::{Error, Result};
use crate::{BasicPrefix, LocationScheme, SelfSigningPrefix, Signer};

/// Extract the AID from an OOBI JSON string.
///
/// Accepts either a single OOBI object or a JSON array of OOBIs.
/// Prefers `cid` from EndRole entries (the transferable AID) over `eid`
/// from LocationScheme entries (which may be a witness basic prefix).
pub fn extract_aid(oobi_json: &str) -> Result<String> {
    use keri_controller::Oobi;

    if let Ok(oobis) = serde_json::from_str::<Vec<Oobi>>(oobi_json) {
        for oobi in &oobis {
            if let Oobi::EndRole(er) = oobi {
                return Ok(er.cid.to_string());
            }
        }
        for oobi in &oobis {
            if let Oobi::Location(loc) = oobi {
                return Ok(loc.eid.to_string());
            }
        }
        Err(Error::CesrParseError("no recognizable OOBI entries".into()))
    } else {
        let oobi: Oobi = serde_json::from_str(oobi_json)
            .map_err(|e| Error::CesrParseError(format!("invalid OOBI JSON: {e}")))?;
        match oobi {
            keri_controller::Oobi::Location(loc) => Ok(loc.eid.to_string()),
            keri_controller::Oobi::EndRole(er) => Ok(er.cid.to_string()),
        }
    }
}

/// Parse a CESR reply stream into a list of signed replies.
///
/// A reply stream contains one or more CESR-encoded reply events,
/// typically produced by `replies_to_cesr_stream`.
pub fn parse_reply_stream(bytes: &[u8]) -> Result<Vec<SignedReply>> {
    let messages = parse_cesr_stream_many(bytes)
        .map_err(|e| Error::CesrParseError(format!("reply stream parse error: {e:?}")))?;

    let mut replies = Vec::new();
    for msg in messages {
        if let Payload::JSON(json) = &msg.payload {
            if let Ok(sr) = serde_json::from_slice::<SignedReply>(json) {
                replies.push(sr);
                continue;
            }
        }
    }
    Ok(replies)
}

/// Serialize signed replies into a CESR byte stream.
///
/// Each reply is wrapped in a `Message::Op(Op::Reply(...))` and
/// CESR-encoded, then concatenated into a single byte stream.
pub fn replies_to_cesr_stream(replies: &[SignedReply]) -> Result<Vec<u8>> {
    replies.iter().try_fold(vec![], |mut acc, sr| {
        let mut cesr = Message::Op(Op::Reply(sr.clone())).to_cesr()?;
        acc.append(&mut cesr);
        Ok(acc)
    })
}

/// Build a signed location-scheme OOBI reply for an identifier.
///
/// Creates a `ReplyEvent` containing the given location scheme, signs it
/// with the provided signer, and returns the `SignedReply`.
pub fn build_location_reply(
    identifier: &BasicPrefix,
    signer: &Signer,
    loc_scheme: LocationScheme,
) -> Result<SignedReply> {
    let reply = ReplyEvent::new_reply(
        ReplyRoute::LocScheme(loc_scheme),
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
    );
    let encoded = reply
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = signer
        .sign(&encoded)
        .map_err(|e| Error::Signing(e.to_string()))?;
    Ok(SignedReply::new_nontrans(
        reply,
        identifier.clone(),
        SelfSigningPrefix::Ed25519Sha512(sig),
    ))
}

/// Build signed OOBI replies for all location schemes associated with an
/// identifier, signing each with the given signer.
pub fn build_location_replies(
    identifier: &BasicPrefix,
    signer: &Signer,
    replies: &[ReplyEvent],
) -> Result<Vec<SignedReply>> {
    replies
        .iter()
        .map(|reply| {
            let encoded = reply
                .encode()
                .map_err(|e| Error::EncodingError(e.to_string()))?;
            let sig = signer
                .sign(&encoded)
                .map_err(|e| Error::Signing(e.to_string()))?;
            Ok(SignedReply::new_nontrans(
                reply.clone(),
                identifier.clone(),
                SelfSigningPrefix::Ed25519Sha512(sig),
            ))
        })
        .collect()
}
