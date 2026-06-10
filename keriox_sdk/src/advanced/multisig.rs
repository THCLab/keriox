//! Direct member-to-member multisig coordination helpers.
//!
//! These helpers let callers route signatures over a group event
//! directly between members (e.g. via Iroh, QUIC, or any peer
//! channel), bypassing the witness mailbox. The normal production
//! flow goes through witnesses — these helpers exist for tests, for
//! offline coordination, and for transports that have their own
//! delivery story.
//!
//! # Workflow
//!
//! 1. The initiator calls
//!    [`Identifier::incept_group`](crate::Identifier::incept_group)
//!    (or `rotate_group`) to build the unsigned group event and the
//!    accompanying exchange messages. They keep the event bytes.
//! 2. Each member signs the event bytes locally with their own
//!    [`SigningBackend`](crate::advanced::operations::SigningBackend) and emits
//!    a `(member_index, SelfSigningPrefix)` pair.
//! 3. The initiator collects every member's pair and calls
//!    [`merge_group_signatures`] to assemble a single
//!    fully-signed [`Notice`].
//! 4. Every member ingests the resulting `Notice` via
//!    [`Identifier::save_notice`](crate::Identifier::save_notice).
//!    Once all sides ingest, the group event is committed to each
//!    member's KEL with all signatures attached.

use keri_controller::SelfSigningPrefix;
use keri_core::event_message::cesr_adapter::{parse_event_type, EventType};
use keri_core::event_message::signed_event_message::Notice;
use keri_core::prefix::IndexedSignature;

use crate::advanced::error::{Error, Result};

/// Combine multiple member signatures over the *same* group event
/// (icp / rot / ixn) into a single fully-signed
/// [`Notice`] ready for [`save_notice`](crate::Identifier::save_notice).
///
/// `event_cesr` must be the canonical event bytes (e.g. the first
/// element of the tuple returned by
/// [`Identifier::incept_group`](crate::Identifier::incept_group) or
/// [`Identifier::rotate_group`](crate::Identifier::rotate_group)) —
/// every member must sign the exact same bytes.
///
/// `signatures` is a list of `(member_index, signature)` pairs where
/// `member_index` is the position of that member's public key in the
/// event's `keys` field. Pass each member's own signing-code-aware
/// signature; mixing curves (e.g. an Ed25519 signature at index 0
/// and a P-256 signature at index 1) is fully supported — each
/// signature carries its own
/// [`SelfSigning`](cesrox::primitives::codes::self_signing::SelfSigning)
/// code, and verifiers dispatch per-index.
///
/// # Errors
/// - [`Error::EncodingError`] if `event_cesr` is not a parseable key event.
pub fn merge_group_signatures(
    event_cesr: &[u8],
    signatures: Vec<(u16, SelfSigningPrefix)>,
) -> Result<Notice> {
    let parsed = parse_event_type(event_cesr)
        .map_err(|e| Error::EncodingError(format!("not a parseable event: {e:?}")))?;
    let key_event = match parsed {
        EventType::KeyEvent(ke) => ke,
        _ => return Err(Error::EncodingError("not a key event (icp/rot/ixn)".into())),
    };

    let indexed_sigs: Vec<IndexedSignature> = signatures
        .into_iter()
        .map(|(idx, sig)| IndexedSignature::new_both_same(sig, idx))
        .collect();

    let signed_message = key_event.sign(indexed_sigs, None, None);
    Ok(Notice::Event(signed_message))
}
