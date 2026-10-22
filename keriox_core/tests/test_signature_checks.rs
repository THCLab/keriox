//! Signatures that do not verify are ignored rather than allowed to spoil
//! the ones that do. The KERI specification:
//! - an event is valid when its verified controller signatures satisfy the
//!   signing threshold, and when its verified witness signatures satisfy the
//!   witness threshold;
//! - a message without at least one verifiable controller signature is
//!   dropped, not escrowed;
//! - a duplicitous event is a verified but different version of an event at
//!   the same location.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signature::Nontransferable,
        signed_event_message::Notice, EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        event_storage::EventStorage,
    },
    signer::Signer,
};
use tempfile::NamedTempFile;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    escrows: EscrowSet<RedbDatabase>,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), Some(bus)),
        storage: EventStorage::new(db),
        escrows,
    }
}

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn witness(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519NT(signer.public_key())
}

fn sig(event: &KeriEvent<KeyEvent>, signer: &Signer) -> SelfSigningPrefix {
    SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap())
}

/// 64 bytes that are no signature of anything.
fn garbage() -> SelfSigningPrefix {
    SelfSigningPrefix::Ed25519Sha512(vec![7u8; 64])
}

fn send(
    fx: &Fixture,
    event: &KeriEvent<KeyEvent>,
    sigs: Vec<IndexedSignature>,
    witness_sigs: Option<Vec<Nontransferable>>,
) -> Result<(), Error> {
    process_notice(
        Notice::Event(event.sign(sigs, witness_sigs, None)),
        &fx.processor,
    )
}

fn sn(fx: &Fixture, id: &IdentifierPrefix) -> Option<u64> {
    fx.storage.get_state(id).map(|state| state.sn)
}

#[test]
fn an_invalid_signature_next_to_enough_valid_ones_is_ignored() {
    let fx = setup();
    let (k0, k1) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&k0), key(&k1)])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![
            IndexedSignature::new_both_same(sig(&icp, &k0), 0),
            IndexedSignature::new_both_same(garbage(), 1),
        ],
        None,
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn an_out_of_range_signature_next_to_enough_valid_ones_is_ignored() {
    let fx = setup();
    let k0 = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&k0)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![
            IndexedSignature::new_both_same(sig(&icp, &k0), 0),
            IndexedSignature::new_both_same(sig(&icp, &k0), 5),
        ],
        None,
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn an_event_without_a_verifiable_signature_is_dropped_not_escrowed() {
    let fx = setup();
    let (k0, k1) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&k0), key(&k1)])
        .with_threshold(&SignatureThreshold::Simple(2))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();

    let refused = send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(garbage(), 0)],
        None,
    );
    assert!(
        matches!(refused, Err(Error::SignatureVerificationError)),
        "{refused:?}"
    );
    assert!(fx
        .escrows
        .partially_signed
        .get_partially_signed_for_event(icp.clone())
        .is_none());

    // The signatures that follow are not blocked by the dropped one.
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &k0), 0)],
        None,
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), None);
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &k1), 1)],
        None,
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn the_partially_signed_escrow_keeps_only_verified_signatures() {
    let fx = setup();
    let (k0, k1) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&k0), key(&k1)])
        .with_threshold(&SignatureThreshold::Simple(2))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    send(
        &fx,
        &icp,
        vec![
            IndexedSignature::new_both_same(sig(&icp, &k0), 0),
            IndexedSignature::new_both_same(garbage(), 1),
        ],
        None,
    )
    .unwrap();
    let escrowed = fx
        .escrows
        .partially_signed
        .get_partially_signed_for_event(icp.clone())
        .unwrap();
    assert_eq!(
        escrowed.signatures,
        vec![IndexedSignature::new_both_same(sig(&icp, &k0), 0)]
    );
}

#[test]
fn an_invalid_signature_cannot_count_towards_the_prior_next_threshold() {
    let fx = setup();
    let current = Signer::new();
    let (next0, next1) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&next0), key(&next1)])
        .with_next_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        None,
    )
    .unwrap();

    // The new signing threshold of 1 is met by next0 alone, but the prior
    // next threshold of 2 is not: the second signature does not verify.
    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&next0), key(&next1)])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let _ = send(
        &fx,
        &rot,
        vec![
            IndexedSignature::new_both_same(sig(&rot, &next0), 0),
            IndexedSignature::new_both_same(garbage(), 1),
        ],
        None,
    );
    assert_eq!(sn(&fx, &id), Some(0));
}

/// An inception with witnesses W1, W2, W3 and bt=2.
fn witnessed_icp(witnesses: &[Signer]) -> (Signer, KeriEvent<KeyEvent>) {
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_witness_list(&witnesses.iter().map(witness).collect::<Vec<_>>())
        .with_witness_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    (current, icp)
}

fn stored_receipt_count(fx: &Fixture, id: &IdentifierPrefix) -> usize {
    fx.storage
        .get_nt_receipts(id, 0)
        .unwrap()
        .map(|rct| {
            rct.signatures
                .iter()
                .map(|group| match group {
                    Nontransferable::Indexed(sigs) => sigs.len(),
                    Nontransferable::Couplet(couplets) => couplets.len(),
                })
                .sum()
        })
        .unwrap_or(0)
}

#[test]
fn an_invalid_witness_signature_next_to_enough_valid_ones_is_ignored() {
    let fx = setup();
    let witnesses = [Signer::new(), Signer::new(), Signer::new()];
    let (current, icp) = witnessed_icp(&witnesses);
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        Some(vec![Nontransferable::Indexed(vec![
            IndexedSignature::new_both_same(sig(&icp, &witnesses[0]), 0),
            IndexedSignature::new_both_same(sig(&icp, &witnesses[1]), 1),
            IndexedSignature::new_both_same(garbage(), 2),
        ])]),
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
    assert_eq!(stored_receipt_count(&fx, &id), 2);
}

#[test]
fn an_out_of_range_witness_signature_next_to_enough_valid_ones_is_ignored() {
    let fx = setup();
    let witnesses = [Signer::new(), Signer::new(), Signer::new()];
    let (current, icp) = witnessed_icp(&witnesses);
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        Some(vec![Nontransferable::Indexed(vec![
            IndexedSignature::new_both_same(sig(&icp, &witnesses[0]), 0),
            IndexedSignature::new_both_same(sig(&icp, &witnesses[1]), 1),
            IndexedSignature::new_both_same(sig(&icp, &witnesses[2]), 5),
        ])]),
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
    assert_eq!(stored_receipt_count(&fx, &id), 2);
}

#[test]
fn a_receipt_arriving_after_the_event_keeps_its_valid_signatures() {
    let fx = setup();
    let witnesses = [Signer::new(), Signer::new(), Signer::new()];
    let (current, icp) = witnessed_icp(&witnesses);
    let id = icp.data.get_prefix();
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        Some(vec![Nontransferable::Indexed(vec![
            IndexedSignature::new_both_same(sig(&icp, &witnesses[0]), 0),
            IndexedSignature::new_both_same(garbage(), 2),
        ])]),
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), None);
    send(
        &fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        Some(vec![Nontransferable::Indexed(vec![
            IndexedSignature::new_both_same(sig(&icp, &witnesses[1]), 1),
        ])]),
    )
    .unwrap();
    assert_eq!(sn(&fx, &id), Some(0));
    assert_eq!(stored_receipt_count(&fx, &id), 2);
}

/// An inception and an interaction, both accepted.
fn two_events(fx: &Fixture) -> (Signer, KeriEvent<KeyEvent>, KeriEvent<KeyEvent>) {
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    send(
        fx,
        &icp,
        vec![IndexedSignature::new_both_same(sig(&icp, &current), 0)],
        None,
    )
    .unwrap();
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&icp.data.get_prefix())
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .build()
        .unwrap();
    send(
        fx,
        &ixn,
        vec![IndexedSignature::new_both_same(sig(&ixn, &current), 0)],
        None,
    )
    .unwrap();
    (current, icp, ixn)
}

/// A different interaction at sn 1.
fn other_ixn(icp: &KeriEvent<KeyEvent>) -> KeriEvent<KeyEvent> {
    EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&icp.data.get_prefix())
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_seal(vec![keri_core::event::sections::seal::Seal::Digest(
            keri_core::event::sections::seal::DigestSeal::new(icp.digest().unwrap()),
        )])
        .build()
        .unwrap()
}

#[test]
fn a_resent_identical_event_is_not_duplicitous() {
    let fx = setup();
    let (current, icp, ixn) = two_events(&fx);
    let id = icp.data.get_prefix();
    send(
        &fx,
        &ixn,
        vec![IndexedSignature::new_both_same(sig(&ixn, &current), 0)],
        None,
    )
    .unwrap();
    assert!(fx.escrows.duplicitous.get(&id).unwrap().is_empty());
    assert_eq!(sn(&fx, &id), Some(1));
}

#[test]
fn an_unverified_different_event_is_dropped_not_duplicitous() {
    let fx = setup();
    let (_current, icp, _ixn) = two_events(&fx);
    let id = icp.data.get_prefix();
    let forged = other_ixn(&icp);
    let refused = send(
        &fx,
        &forged,
        vec![IndexedSignature::new_both_same(garbage(), 0)],
        None,
    );
    assert!(
        matches!(refused, Err(Error::SignatureVerificationError)),
        "{refused:?}"
    );
    assert!(fx.escrows.duplicitous.get(&id).unwrap().is_empty());
}

#[test]
fn a_verified_different_event_is_duplicitous() {
    let fx = setup();
    let (current, icp, ixn) = two_events(&fx);
    let id = icp.data.get_prefix();
    let other = other_ixn(&icp);
    send(
        &fx,
        &other,
        vec![IndexedSignature::new_both_same(sig(&other, &current), 0)],
        None,
    )
    .unwrap();
    let evidence = fx.escrows.duplicitous.get(&id).unwrap();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].event_message, other);
    assert_eq!(
        fx.storage.get_state(&id).unwrap().last_event_digest,
        ixn.digest().unwrap().into()
    );
}
