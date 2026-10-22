//! The backer (witness) list rules of the KERI specification:
//! - witness AIDs are non-transferable public keys;
//! - an AID appears at most once in `b`, in `br` and in `ba`;
//! - `bt` is an integer, 0 when `b` is empty, and at most the number of
//!   witnesses;
//! - `ba` adds an AID only when it is not already a witness.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use tempfile::NamedTempFile;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), None),
        storage: EventStorage::new(db),
    }
}

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn witness() -> BasicPrefix {
    BasicPrefix::Ed25519NT(Signer::new().public_key())
}

fn send(fx: &Fixture, event: &KeriEvent<KeyEvent>, signer: &Signer) -> Result<(), Error> {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)),
        &fx.processor,
    )
}

/// Sends an inception with witnesses `b` and threshold `bt`, signed by a
/// fresh key; returns the outcome and the identifier.
fn incept(
    fx: &Fixture,
    b: &[BasicPrefix],
    bt: SignatureThreshold,
) -> (Result<(), Error>, IdentifierPrefix) {
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_witness_list(b)
        .with_witness_threshold(&bt)
        .build()
        .unwrap();
    (send(fx, &icp, &current), icp.data.get_prefix())
}

fn refused(fx: &Fixture, b: &[BasicPrefix], bt: SignatureThreshold) {
    let (outcome, id) = incept(fx, b, bt);
    assert!(
        matches!(outcome, Err(Error::SemanticError(_))),
        "{outcome:?}"
    );
    assert!(fx.storage.get_state(&id).is_none());
}

#[test]
fn a_witness_aid_is_non_transferable() {
    let fx = setup();
    refused(
        &fx,
        &[BasicPrefix::Ed25519(Signer::new().public_key())],
        SignatureThreshold::Simple(0),
    );
}

#[test]
fn a_witness_appears_once() {
    let fx = setup();
    let w = witness();
    refused(&fx, &[w.clone(), w], SignatureThreshold::Simple(0));
}

#[test]
fn the_witness_threshold_is_zero_without_witnesses() {
    let fx = setup();
    refused(&fx, &[], SignatureThreshold::Simple(1));
}

#[test]
fn the_witness_threshold_fits_the_witnesses() {
    let fx = setup();
    refused(&fx, &[witness()], SignatureThreshold::Simple(2));
}

#[test]
fn the_witness_threshold_is_an_integer() {
    let fx = setup();
    refused(
        &fx,
        &[witness(), witness()],
        SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]),
    );
}

/// An identifier with witness `w` (bt=0, so no receipts are needed), and a
/// rotation of it with the given `br`, `ba`.
fn rotation(
    fx: &Fixture,
    w: &BasicPrefix,
    br: &[BasicPrefix],
    ba: &[BasicPrefix],
) -> (Result<(), Error>, IdentifierPrefix) {
    let (current, next) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&next)])
        .with_witness_list(&[w.clone()])
        .with_witness_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap();
    send(fx, &icp, &current).unwrap();
    let id = icp.data.get_prefix();
    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&next)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_witness_to_remove(br)
        .with_witness_to_add(ba)
        .with_witness_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap();
    (send(fx, &rot, &next), id)
}

#[test]
fn an_aid_appears_once_in_the_removed_witnesses() {
    let fx = setup();
    let w = witness();
    let (outcome, id) = rotation(&fx, &w, &[w.clone(), w.clone()], &[]);
    assert!(
        matches!(outcome, Err(Error::SemanticError(_))),
        "{outcome:?}"
    );
    assert_eq!(fx.storage.get_state(&id).unwrap().sn, 0);
}

#[test]
fn an_aid_appears_once_in_the_added_witnesses() {
    let fx = setup();
    let added = witness();
    let (outcome, id) = rotation(&fx, &witness(), &[], &[added.clone(), added]);
    assert!(
        matches!(outcome, Err(Error::SemanticError(_))),
        "{outcome:?}"
    );
    assert_eq!(fx.storage.get_state(&id).unwrap().sn, 0);
}

#[test]
fn an_added_transferable_witness_is_refused() {
    let fx = setup();
    let (outcome, id) = rotation(
        &fx,
        &witness(),
        &[],
        &[BasicPrefix::Ed25519(Signer::new().public_key())],
    );
    assert!(
        matches!(outcome, Err(Error::SemanticError(_))),
        "{outcome:?}"
    );
    assert_eq!(fx.storage.get_state(&id).unwrap().sn, 0);
}

#[test]
fn adding_a_current_witness_keeps_it_once() {
    let fx = setup();
    let w = witness();
    let added = witness();
    let (outcome, id) = rotation(&fx, &w, &[], &[w.clone(), added.clone()]);
    outcome.unwrap();
    let state = fx.storage.get_state(&id).unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.witness_config.witnesses, vec![w, added]);
}
