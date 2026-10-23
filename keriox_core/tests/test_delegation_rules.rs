//! A delegated event is valid only once its delegator approves it: some
//! event of the delegator's KEL anchors the delegated event's seal, whose
//! `i`, `s` and `d` all name the delegated event (KERI specification,
//! Cooperative Delegation). The source seal attached to the delegated event
//! points at the delegating event; without one, the validator finds the
//! anchor in the delegator's KEL.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    event::{
        sections::seal::{EventSeal, Seal, SourceSeal},
        KeyEvent,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
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
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), Some(bus)),
        storage: EventStorage::new(db),
    }
}

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn send(fx: &Fixture, event: &KeriEvent<KeyEvent>, signer: &Signer, seal: Option<SourceSeal>) {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    let _ = process_notice(
        Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, seal)),
        &fx.processor,
    );
}

fn sn(fx: &Fixture, id: &IdentifierPrefix) -> Option<u64> {
    fx.storage.get_state(id).map(|state| state.sn)
}

struct Delegation {
    delegator: Signer,
    delegator_icp: KeriEvent<KeyEvent>,
    delegate: Signer,
    dip: KeriEvent<KeyEvent>,
}

/// A delegator (accepted) and a delegated inception under it (not sent).
fn delegation(fx: &Fixture) -> Delegation {
    let delegator = Signer::new();
    let delegator_icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&delegator)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    send(fx, &delegator_icp, &delegator, None);
    let delegate = Signer::new();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&delegator_icp.data.get_prefix())
        .with_keys(vec![key(&delegate)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    Delegation {
        delegator,
        delegator_icp,
        delegate,
        dip,
    }
}

/// The delegator's interaction anchoring `seal`.
fn anchor(fx: &Fixture, d: &Delegation, seal: EventSeal) -> KeriEvent<KeyEvent> {
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&d.delegator_icp.data.get_prefix())
        .with_sn(1)
        .with_previous_event(&d.delegator_icp.digest().unwrap())
        .with_seal(vec![Seal::Event(seal)])
        .build()
        .unwrap();
    send(fx, &ixn, &d.delegator, None);
    ixn
}

fn seal_of(event: &KeriEvent<KeyEvent>) -> EventSeal {
    EventSeal::new(
        event.data.get_prefix(),
        event.data.get_sn(),
        event.digest().unwrap(),
    )
}

#[test]
fn the_anchoring_seal_names_the_delegated_event() {
    let fx = setup();
    let d = delegation(&fx);
    let ixn = anchor(&fx, &d, seal_of(&d.dip));
    send(
        &fx,
        &d.dip,
        &d.delegate,
        Some(SourceSeal::new(1, ixn.digest().unwrap())),
    );
    assert_eq!(sn(&fx, &d.dip.data.get_prefix()), Some(0));
}

#[test]
fn a_seal_with_another_identifier_does_not_approve() {
    let fx = setup();
    let d = delegation(&fx);
    let other = d.delegator_icp.data.get_prefix();
    let ixn = anchor(&fx, &d, EventSeal::new(other, 0, d.dip.digest().unwrap()));
    send(
        &fx,
        &d.dip,
        &d.delegate,
        Some(SourceSeal::new(1, ixn.digest().unwrap())),
    );
    assert_eq!(sn(&fx, &d.dip.data.get_prefix()), None);
}

#[test]
fn a_seal_with_another_sequence_number_does_not_approve() {
    let fx = setup();
    let d = delegation(&fx);
    let ixn = anchor(
        &fx,
        &d,
        EventSeal::new(d.dip.data.get_prefix(), 1, d.dip.digest().unwrap()),
    );
    send(
        &fx,
        &d.dip,
        &d.delegate,
        Some(SourceSeal::new(1, ixn.digest().unwrap())),
    );
    assert_eq!(sn(&fx, &d.dip.data.get_prefix()), None);
}

#[test]
fn without_a_source_seal_the_anchor_is_found_in_the_delegators_kel() {
    let fx = setup();
    let d = delegation(&fx);
    anchor(&fx, &d, seal_of(&d.dip));
    send(&fx, &d.dip, &d.delegate, None);
    assert_eq!(sn(&fx, &d.dip.data.get_prefix()), Some(0));
}

#[test]
fn a_source_seal_naming_an_event_that_anchors_nothing_does_not_approve() {
    let fx = setup();
    let d = delegation(&fx);
    send(
        &fx,
        &d.dip,
        &d.delegate,
        Some(SourceSeal::new(0, d.delegator_icp.digest().unwrap())),
    );
    assert_eq!(sn(&fx, &d.dip.data.get_prefix()), None);
}

/// A delegator with a basic prefix, whose inception can anchor a delegated
/// event that names it.
fn delegator_inception_anchors(fx: &Fixture, source_seal: bool) {
    let delegator = Signer::new();
    let delegator_id = IdentifierPrefix::Basic(key(&delegator));
    let delegate = Signer::new();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&delegator_id)
        .with_keys(vec![key(&delegate)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_prefix(&delegator_id)
        .with_keys(vec![key(&delegator)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_seal(vec![Seal::Event(seal_of(&dip))])
        .build()
        .unwrap();
    send(fx, &icp, &delegator, None);
    assert_eq!(sn(fx, &delegator_id), Some(0));

    let seal = source_seal.then(|| SourceSeal::new(0, icp.digest().unwrap()));
    send(fx, &dip, &delegate, seal);
    assert_eq!(sn(fx, &dip.data.get_prefix()), Some(0));
}

#[test]
fn the_delegators_inception_can_anchor() {
    delegator_inception_anchors(&setup(), true);
}

#[test]
fn the_delegators_inception_is_found_without_a_source_seal() {
    delegator_inception_anchors(&setup(), false);
}

#[test]
fn a_delegated_rotation_arriving_before_its_inception_and_anchors_is_accepted() {
    let fx = setup();
    let d = delegation(&fx);
    let delegator_id = d.delegator_icp.data.get_prefix();
    let delegate_next = Signer::new();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&delegator_id)
        .with_keys(vec![key(&d.delegate)])
        .with_next_keys(vec![key(&delegate_next)])
        .build()
        .unwrap();
    let id = dip.data.get_prefix();
    let drt = EventMsgBuilder::new(EventTypeTag::Drt)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&dip.digest().unwrap())
        .with_keys(vec![key(&delegate_next)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let ixn1 = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&delegator_id)
        .with_sn(1)
        .with_previous_event(&d.delegator_icp.digest().unwrap())
        .with_seal(vec![Seal::Event(seal_of(&dip))])
        .build()
        .unwrap();
    let ixn2 = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&delegator_id)
        .with_sn(2)
        .with_previous_event(&ixn1.digest().unwrap())
        .with_seal(vec![Seal::Event(seal_of(&drt))])
        .build()
        .unwrap();

    send(
        &fx,
        &dip,
        &d.delegate,
        Some(SourceSeal::new(1, ixn1.digest().unwrap())),
    );
    send(
        &fx,
        &drt,
        &delegate_next,
        Some(SourceSeal::new(2, ixn2.digest().unwrap())),
    );
    send(&fx, &ixn1, &d.delegator, None);
    assert_eq!(sn(&fx, &id), Some(0));
    send(&fx, &ixn2, &d.delegator, None);
    assert_eq!(sn(&fx, &id), Some(1));
}
