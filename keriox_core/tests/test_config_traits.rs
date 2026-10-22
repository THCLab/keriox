//! Configuration traits of an inception constrain the whole KEL, and the
//! KERI specification makes validators drop any event that breaks them:
//! - `EO` (establishment only): no interaction events;
//! - `DND` (do not delegate): no delegated events approved by this AID.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
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

fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer, seal: Option<SourceSeal>) -> Notice {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, seal))
}

fn sn(fx: &Fixture, id: &IdentifierPrefix) -> Option<u64> {
    fx.storage.get_state(id).map(|state| state.sn)
}

fn incept(fx: &Fixture, current: &Signer, next: &Signer, traits: &[&str]) -> KeriEvent<KeyEvent> {
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(current)])
        .with_next_keys(vec![key(next)])
        .with_config_traits(traits)
        .build()
        .unwrap();
    process_notice(signed(&icp, current, None), &fx.processor).unwrap();
    icp
}

#[test]
fn an_establishment_only_kel_drops_interaction_events() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(&fx, &current, &next, &["EO"]);
    let id = icp.data.get_prefix();
    assert_eq!(sn(&fx, &id), Some(0));

    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .build()
        .unwrap();
    assert!(matches!(
        process_notice(signed(&ixn, &current, None), &fx.processor),
        Err(Error::ConfigTraitViolation(_))
    ));
    assert_eq!(sn(&fx, &id), Some(0));

    // Rotations remain the way to add events.
    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&next)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    process_notice(signed(&rot, &next, None), &fx.processor).unwrap();
    assert_eq!(sn(&fx, &id), Some(1));
}

#[test]
fn interaction_events_are_allowed_without_establishment_only() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(&fx, &current, &next, &["DND"]);
    let id = icp.data.get_prefix();
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .build()
        .unwrap();
    process_notice(signed(&ixn, &current, None), &fx.processor).unwrap();
    assert_eq!(sn(&fx, &id), Some(1));
}

/// A delegate incepted under `delegator`, anchored in its interaction
/// event. Returns the delegate's prefix after processing both.
fn delegate_under(fx: &Fixture, traits: &[&str]) -> IdentifierPrefix {
    let (delegator, delegator_next) = (Signer::new(), Signer::new());
    let delegator_icp = incept(fx, &delegator, &delegator_next, traits);
    let delegator_id = delegator_icp.data.get_prefix();

    let delegate = Signer::new();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&delegator_id)
        .with_keys(vec![key(&delegate)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let anchor = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&delegator_id)
        .with_sn(1)
        .with_previous_event(&delegator_icp.digest().unwrap())
        .with_seal(vec![Seal::Event(EventSeal::new(
            dip.data.get_prefix(),
            0,
            dip.digest().unwrap(),
        ))])
        .build()
        .unwrap();
    process_notice(signed(&anchor, &delegator, None), &fx.processor).unwrap();
    let _ = process_notice(
        signed(
            &dip,
            &delegate,
            Some(SourceSeal::new(1, anchor.digest().unwrap())),
        ),
        &fx.processor,
    );
    dip.data.get_prefix()
}

#[test]
fn a_do_not_delegate_kel_cannot_approve_delegations() {
    let fx = setup();
    let delegate = delegate_under(&fx, &["DND"]);
    assert_eq!(sn(&fx, &delegate), None);
}

#[test]
fn a_delegator_without_do_not_delegate_approves_delegations() {
    let fx = setup();
    let delegate = delegate_under(&fx, &[]);
    assert_eq!(sn(&fx, &delegate), Some(0));
}
