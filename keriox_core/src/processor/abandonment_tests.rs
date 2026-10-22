//! An identifier is abandoned by an establishment event that commits to no
//! next keys (`n=[]`, `nt=0`). Nothing may follow it: no rotation can reveal
//! a committed key, and the last keys may no longer add interaction events.

use std::sync::Arc;

use said::SelfAddressingIdentifier;
use tempfile::NamedTempFile;

use crate::{
    database::{redb::RedbDatabase, EscrowDatabase},
    error::Error,
    event::{
        sections::{
            seal::{EventSeal, Seal, SourceSeal},
            threshold::SignatureThreshold,
        },
        KeyEvent,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        event_storage::EventStorage,
        Processor,
    },
    signer::Signer,
    state::{Abandonment, IdentifierState},
};

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

/// Signs `event` with `signer` at current index `index`, which is also its
/// index in the prior next key list.
fn signed(
    event: &KeriEvent<KeyEvent>,
    signer: &Signer,
    index: u16,
    delegator_seal: Option<SourceSeal>,
) -> Notice {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    Notice::Event(event.sign(
        vec![IndexedSignature::new_both_same(sig, index)],
        None,
        delegator_seal,
    ))
}

fn state(fx: &Fixture, id: &IdentifierPrefix) -> Option<IdentifierState> {
    fx.storage.get_state(id)
}

fn incept(fx: &Fixture, current: &Signer, next: &[BasicPrefix]) -> KeriEvent<KeyEvent> {
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(current)])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(next.to_vec())
        .with_next_threshold(&SignatureThreshold::Simple(next.len().min(1) as u64))
        .build()
        .unwrap();
    fx.processor
        .process_notice(&signed(&icp, current, 0, None))
        .unwrap();
    icp
}

fn abandonment(
    tag: EventTypeTag,
    id: &IdentifierPrefix,
    sn: u64,
    previous: &SelfAddressingIdentifier,
    revealed: &Signer,
) -> KeriEvent<KeyEvent> {
    EventMsgBuilder::new(tag)
        .with_prefix(id)
        .with_sn(sn)
        .with_previous_event(previous)
        .with_keys(vec![key(revealed)])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![])
        .with_next_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap()
}

/// Incepts an identifier and abandons it at sn 1, signed by the revealed
/// next key. Returns the identifier, the abandonment event and its signer.
fn abandoned(fx: &Fixture) -> (IdentifierPrefix, KeriEvent<KeyEvent>, Signer) {
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(fx, &current, &[key(&next)]);
    let id = icp.data.get_prefix();
    let rot = abandonment(EventTypeTag::Rot, &id, 1, &icp.digest().unwrap(), &next);
    fx.processor
        .process_notice(&signed(&rot, &next, 0, None))
        .unwrap();
    assert_eq!(state(fx, &id).unwrap().sn, 1);
    (id, rot, next)
}

fn ixn(id: &IdentifierPrefix, sn: u64, previous: &SelfAddressingIdentifier) -> KeriEvent<KeyEvent> {
    EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(id)
        .with_sn(sn)
        .with_previous_event(previous)
        .build()
        .unwrap()
}

#[test]
fn abandoned_state_reports_the_abandonment_event() {
    let fx = setup();
    let (id, rot, _) = abandoned(&fx);

    let state = state(&fx, &id).unwrap();
    assert!(state.is_abandoned());
    assert_eq!(state.abandonment(), Some((1, rot.digest().unwrap())));

    // Anyone reading the key state sees the empty commitment.
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(json["nt"], "0");
    assert_eq!(json["n"], serde_json::json!([]));
}

#[test]
fn a_live_identifier_is_not_abandoned() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let id = incept(&fx, &current, &[key(&next)]).data.get_prefix();

    let state = state(&fx, &id).unwrap();
    assert!(!state.is_abandoned());
    assert_eq!(state.abandonment(), None);
    assert!(!IdentifierState::default().is_abandoned());
}

#[test]
fn rotation_after_abandonment_is_refused() {
    let fx = setup();
    let (id, rot, _) = abandoned(&fx);

    // Nt=0 is satisfied by no signatures, so without the rule anyone could
    // rotate to keys of their choosing.
    let attacker = Signer::new();
    let takeover = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(2)
        .with_previous_event(&rot.digest().unwrap())
        .with_keys(vec![key(&attacker)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();

    assert!(matches!(
        fx.processor.process_notice(&signed(&takeover, &attacker, 0, None)),
        Err(Error::AbandonedIdentifier(refused)) if refused == id
    ));
    assert_eq!(state(&fx, &id).unwrap().sn, 1);
}

#[test]
fn interaction_after_abandonment_is_refused() {
    let fx = setup();
    let (id, rot, last_keys) = abandoned(&fx);

    let ixn = ixn(&id, 2, &rot.digest().unwrap());
    assert!(matches!(
        fx.processor
            .process_notice(&signed(&ixn, &last_keys, 0, None)),
        Err(Error::AbandonedIdentifier(_))
    ));
    assert_eq!(state(&fx, &id).unwrap().sn, 1);
}

#[test]
fn a_far_future_event_after_abandonment_is_refused_not_escrowed() {
    let fx = setup();
    let (id, rot, last_keys) = abandoned(&fx);

    let ixn = ixn(&id, 5, &rot.digest().unwrap());
    assert!(matches!(
        fx.processor
            .process_notice(&signed(&ixn, &last_keys, 0, None)),
        Err(Error::AbandonedIdentifier(_))
    ));
    let escrowed = fx
        .escrows
        .out_of_order
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap()
        .count();
    assert_eq!(escrowed, 0);
}

#[test]
fn applying_to_an_abandoned_state_is_refused() {
    // The partially witnessed escrow applies events to the state directly,
    // without the validator, so the rule must live in the state transition.
    let fx = setup();
    let (id, rot, _) = abandoned(&fx);

    let ixn = ixn(&id, 2, &rot.digest().unwrap());
    assert!(matches!(
        state(&fx, &id).unwrap().apply(&ixn),
        Err(Error::AbandonedIdentifier(_))
    ));
}

#[test]
fn a_competing_event_at_the_abandonment_sn_is_only_duplicitous() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(&fx, &current, &[key(&next)]);
    let id = icp.data.get_prefix();
    let rot = abandonment(EventTypeTag::Rot, &id, 1, &icp.digest().unwrap(), &next);
    fx.processor
        .process_notice(&signed(&rot, &next, 0, None))
        .unwrap();

    let competing = ixn(&id, 1, &icp.digest().unwrap());
    fx.processor
        .process_notice(&signed(&competing, &current, 0, None))
        .unwrap();

    let state = state(&fx, &id).unwrap();
    assert_eq!(state.sn, 1);
    assert_eq!(state.abandonment(), Some((1, rot.digest().unwrap())));
    assert_eq!(fx.escrows.duplicitous.get(&id).unwrap().len(), 1);
}

#[test]
fn an_early_event_is_dropped_from_escrow_once_the_abandonment_lands() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(&fx, &current, &[key(&next)]);
    let id = icp.data.get_prefix();
    let rot = abandonment(EventTypeTag::Rot, &id, 1, &icp.digest().unwrap(), &next);

    // Arrives before the abandonment, so it can only wait as out of order.
    let early = ixn(&id, 2, &rot.digest().unwrap());
    fx.processor
        .process_notice(&signed(&early, &next, 0, None))
        .unwrap();
    let escrowed = |fx: &Fixture| {
        fx.escrows
            .out_of_order
            .escrowed_out_of_order
            .get_from_sn(&id, 0)
            .unwrap()
            .count()
    };
    assert_eq!(escrowed(&fx), 1);

    fx.processor
        .process_notice(&signed(&rot, &next, 0, None))
        .unwrap();

    assert_eq!(state(&fx, &id).unwrap().sn, 1);
    assert_eq!(escrowed(&fx), 0);
}

#[test]
fn an_inception_without_next_keys_is_non_transferable_not_abandoned() {
    // The spec: an empty `n` in an inception makes the identifier
    // non-transferable, in a rotation abandoned. Either way no more key
    // events are allowed, but only an abandoned identifier stops speaking
    // for itself.
    let fx = setup();
    let current = Signer::new();
    let icp = incept(&fx, &current, &[]);
    let id = icp.data.get_prefix();

    let after_icp = state(&fx, &id).unwrap();
    assert!(!after_icp.is_transferable());
    assert!(!after_icp.is_abandoned());
    assert_eq!(after_icp.abandonment(), None);
    let status = fx.storage.get_status(&id).unwrap();
    assert!(!status.transferable);
    assert_eq!(status.abandoned, None);

    let ixn = ixn(&id, 1, &icp.digest().unwrap());
    assert!(matches!(
        fx.processor
            .process_notice(&signed(&ixn, &current, 0, None)),
        Err(Error::NonTransferableIdentifier(refused)) if refused == id
    ));
    assert_eq!(state(&fx, &id).unwrap().sn, 0);

    // Its keys still speak for it: its messages are not refused.
    assert!(fx.storage.refuse_abandoned_signer(Some(&id)).is_ok());
}

/// Next key commitments whose threshold does not fit the listed digests,
/// refused as the KERI specification requires: an integer threshold may not
/// need more keys than are committed, and a weighted one lists exactly one
/// weight per digest. So no next keys means threshold 0.
fn unsound_next_commitments() -> Vec<(Vec<BasicPrefix>, SignatureThreshold)> {
    let (a, b) = (key(&Signer::new()), key(&Signer::new()));
    vec![
        (vec![], SignatureThreshold::Simple(1)),
        (vec![], SignatureThreshold::single_weighted(vec![(1, 2)])),
        (vec![a.clone()], SignatureThreshold::Simple(2)),
        (
            vec![a.clone(), b.clone()],
            SignatureThreshold::single_weighted(vec![(1, 2), (1, 2), (1, 2)]),
        ),
        (vec![a, b], SignatureThreshold::single_weighted(vec![(1, 1)])),
    ]
}

#[test]
fn a_zero_next_threshold_with_next_keys_is_accepted() {
    // The specification allows nt=0 with committed keys (M of N with M=0):
    // the controller chose a threshold any rotation meets. Only an empty
    // `n` ends the log.
    let fx = setup();
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_next_threshold(&SignatureThreshold::Simple(0))
        .build()
        .unwrap();
    fx.processor
        .process_notice(&signed(&icp, &current, 0, None))
        .unwrap();
    assert!(state(&fx, &icp.data.get_prefix()).unwrap().is_transferable());
}

#[test]
fn inception_with_an_unsound_next_commitment_is_refused() {
    for (next, threshold) in unsound_next_commitments() {
        let fx = setup();
        let current = Signer::new();
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(&current)])
            .with_next_keys(next.clone())
            .with_next_threshold(&threshold)
            .build()
            .unwrap();
        assert!(
            matches!(
                fx.processor
                    .process_notice(&signed(&icp, &current, 0, None)),
                Err(Error::SemanticError(_))
            ),
            "n={next:?} nt={threshold:?} was accepted"
        );
        assert!(state(&fx, &icp.data.get_prefix()).is_none());
    }
}

#[test]
fn rotation_with_an_unsound_next_commitment_is_refused() {
    for (next_keys, threshold) in unsound_next_commitments() {
        let fx = setup();
        let (current, next) = (Signer::new(), Signer::new());
        let icp = incept(&fx, &current, &[key(&next)]);
        let id = icp.data.get_prefix();
        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&id)
            .with_sn(1)
            .with_previous_event(&icp.digest().unwrap())
            .with_keys(vec![key(&next)])
            .with_next_keys(next_keys.clone())
            .with_next_threshold(&threshold)
            .build()
            .unwrap();
        assert!(
            matches!(
                fx.processor.process_notice(&signed(&rot, &next, 0, None)),
                Err(Error::SemanticError(_))
            ),
            "n={next_keys:?} nt={threshold:?} was accepted"
        );
        assert_eq!(state(&fx, &id).unwrap().sn, 0);
    }
}

/// A delegator and a delegate it has approved. Returns the delegator's
/// signer and latest event, and the delegate's prefix and inception.
struct Delegation {
    delegator: Signer,
    delegator_last: KeriEvent<KeyEvent>,
    delegate: IdentifierPrefix,
    dip: KeriEvent<KeyEvent>,
}

fn delegation(
    fx: &Fixture,
    delegate_current: &Signer,
    delegate_next: &[BasicPrefix],
) -> Delegation {
    let delegator = Signer::new();
    let delegator_icp = incept(fx, &delegator, &[key(&Signer::new())]);
    let delegator_id = delegator_icp.data.get_prefix();

    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&delegator_id)
        .with_keys(vec![key(delegate_current)])
        .with_next_keys(delegate_next.to_vec())
        .with_next_threshold(&SignatureThreshold::Simple(
            delegate_next.len().min(2) as u64
        ))
        .build()
        .unwrap();
    let delegate = dip.data.get_prefix();
    let anchor = approve(fx, &delegator, &delegator_icp, &dip);
    fx.processor
        .process_notice(&signed(
            &dip,
            delegate_current,
            0,
            Some(SourceSeal::new(1, anchor.digest().unwrap())),
        ))
        .unwrap();
    assert_eq!(state(fx, &delegate).unwrap().sn, 0);

    Delegation {
        delegator,
        delegator_last: anchor,
        delegate,
        dip,
    }
}

/// The delegator anchors `delegated` in an interaction event after `last`.
fn approve(
    fx: &Fixture,
    delegator: &Signer,
    last: &KeriEvent<KeyEvent>,
    delegated: &KeriEvent<KeyEvent>,
) -> KeriEvent<KeyEvent> {
    let anchor = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&last.data.get_prefix())
        .with_sn(last.data.get_sn() + 1)
        .with_previous_event(&last.digest().unwrap())
        .with_seal(vec![Seal::Event(EventSeal::new(
            delegated.data.get_prefix(),
            delegated.data.get_sn(),
            delegated.digest().unwrap(),
        ))])
        .build()
        .unwrap();
    fx.processor
        .process_notice(&signed(&anchor, delegator, 0, None))
        .unwrap();
    anchor
}

#[test]
fn delegated_rotation_after_abandonment_is_refused() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let d = delegation(&fx, &current, &[key(&next)]);

    let drt = abandonment(
        EventTypeTag::Drt,
        &d.delegate,
        1,
        &d.dip.digest().unwrap(),
        &next,
    );
    let anchor = approve(&fx, &d.delegator, &d.delegator_last, &drt);
    fx.processor
        .process_notice(&signed(
            &drt,
            &next,
            0,
            Some(SourceSeal::new(
                anchor.data.get_sn(),
                anchor.digest().unwrap(),
            )),
        ))
        .unwrap();
    let after = state(&fx, &d.delegate).unwrap();
    assert_eq!(after.sn, 1);
    assert!(after.is_abandoned());

    let attacker = Signer::new();
    let takeover = EventMsgBuilder::new(EventTypeTag::Drt)
        .with_prefix(&d.delegate)
        .with_sn(2)
        .with_previous_event(&drt.digest().unwrap())
        .with_keys(vec![key(&attacker)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let anchor = approve(&fx, &d.delegator, &anchor, &takeover);
    assert!(matches!(
        fx.processor.process_notice(&signed(
            &takeover,
            &attacker,
            0,
            Some(SourceSeal::new(
                anchor.data.get_sn(),
                anchor.digest().unwrap()
            )),
        )),
        Err(Error::AbandonedIdentifier(_))
    ));
    assert_eq!(state(&fx, &d.delegate).unwrap().sn, 1);
}

#[test]
fn delegated_rotation_needs_the_prior_next_threshold() {
    // Two next keys with nt=2: revealing both but signing with one of them
    // satisfies kt=1, yet only half of the prior commitment signed.
    let fx = setup();
    let current = Signer::new();
    let (a, b) = (Signer::new(), Signer::new());
    let d = delegation(&fx, &current, &[key(&a), key(&b)]);

    let drt = EventMsgBuilder::new(EventTypeTag::Drt)
        .with_prefix(&d.delegate)
        .with_sn(1)
        .with_previous_event(&d.dip.digest().unwrap())
        .with_keys(vec![key(&a), key(&b)])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let anchor = approve(&fx, &d.delegator, &d.delegator_last, &drt);
    let _ = fx.processor.process_notice(&signed(
        &drt,
        &a,
        0,
        Some(SourceSeal::new(
            anchor.data.get_sn(),
            anchor.digest().unwrap(),
        )),
    ));

    assert_eq!(state(&fx, &d.delegate).unwrap().sn, 0);
}

#[test]
fn status_reports_the_abandonment() {
    let fx = setup();
    let (id, rot, _) = abandoned(&fx);

    let status = fx.storage.get_status(&id).unwrap();
    assert_eq!(
        status.abandoned,
        Some(Abandonment {
            sn: 1,
            said: rot.digest().unwrap()
        })
    );
    assert!(!status.transferable);
    let json = serde_json::to_value(&status).unwrap();
    assert_eq!(json["abandoned"]["sn"], 1);
    assert_eq!(json["abandoned"]["said"], rot.digest().unwrap().to_string());
}

#[test]
fn a_live_identifier_has_no_abandonment_in_its_status() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let id = incept(&fx, &current, &[key(&next)]).data.get_prefix();

    let json = serde_json::to_value(fx.storage.get_status(&id).unwrap()).unwrap();
    assert_eq!(json["transferable"], true);
    assert_eq!(json["abandoned"], serde_json::Value::Null);
    assert_eq!(json["sn"], 0);
}

#[test]
fn only_an_abandoned_signer_is_refused() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let live = incept(&fx, &current, &[key(&next)]).data.get_prefix();
    let (gone, _, _) = abandoned(&fx);
    let unknown = IdentifierPrefix::Basic(key(&Signer::new()));

    assert!(fx.storage.refuse_abandoned_signer(Some(&live)).is_ok());
    assert!(fx.storage.refuse_abandoned_signer(Some(&unknown)).is_ok());
    assert!(fx.storage.refuse_abandoned_signer(None).is_ok());
    assert!(matches!(
        fx.storage.refuse_abandoned_signer(Some(&gone)),
        Err(Error::AbandonedIdentifier(refused)) if refused == gone
    ));
}

#[cfg(feature = "oobi-manager")]
#[test]
fn an_end_role_reply_from_an_abandoned_identifier_is_refused() {
    use crate::{
        actor::{event_generator::generate_end_role, process_signed_oobi},
        oobi::Role,
        oobi_manager::OobiManager,
        query::reply_event::SignedReply,
    };

    let fx = setup();
    let (id, rot, last_keys) = abandoned(&fx);
    let oobi_manager = OobiManager::new(fx.storage.events_db.clone()).unwrap();

    let watcher = IdentifierPrefix::Basic(key(&Signer::new()));
    let rpy = generate_end_role(&id, &watcher, Role::Watcher, true);
    let sig = SelfSigningPrefix::Ed25519Sha512(last_keys.sign(rpy.encode().unwrap()).unwrap());
    let signed = SignedReply::new_trans(
        rpy,
        EventSeal::new(id.clone(), 1, rot.digest().unwrap()),
        vec![IndexedSignature::new_both_same(sig, 0)],
    );

    assert!(matches!(
        process_signed_oobi(&signed, &oobi_manager, &fx.storage),
        Err(Error::AbandonedIdentifier(_))
    ));
    assert!(oobi_manager
        .get_end_role(&id, Role::Watcher)
        .unwrap()
        .unwrap_or_default()
        .is_empty());
}

#[test]
fn the_generated_abandonment_is_accepted_and_nothing_is_generated_after_it() {
    use crate::actor::event_generator;

    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let icp = incept(&fx, &current, &[key(&next)]);
    let id = icp.data.get_prefix();

    let rot = event_generator::abandon(
        state(&fx, &id).unwrap(),
        vec![key(&next)],
        1,
        vec![],
        vec![],
        0,
        vec![],
    )
    .unwrap();
    assert_eq!(rot.event_type, EventTypeTag::Rot);
    fx.processor
        .process_notice(&signed(&rot, &next, 0, None))
        .unwrap();
    let after = state(&fx, &id).unwrap();
    assert!(after.is_abandoned());

    assert!(matches!(
        event_generator::anchor(after.clone(), &[]),
        Err(Error::AbandonedIdentifier(_))
    ));
    assert!(matches!(
        event_generator::rotate(
            after.clone(),
            vec![key(&next)],
            vec![key(&Signer::new())],
            1,
            vec![],
            vec![],
            0
        ),
        Err(Error::AbandonedIdentifier(_))
    ));
    assert!(matches!(
        event_generator::abandon(after, vec![key(&next)], 1, vec![], vec![], 0, vec![]),
        Err(Error::AbandonedIdentifier(_))
    ));
}

#[test]
fn a_delegated_identifier_rotates_and_abandons_with_drt() {
    use crate::actor::event_generator;

    let fx = setup();
    let (current, next, after_next) = (Signer::new(), Signer::new(), Signer::new());
    let d = delegation(&fx, &current, &[key(&next)]);

    let raw = event_generator::rotate(
        state(&fx, &d.delegate).unwrap(),
        vec![key(&next)],
        vec![key(&after_next)],
        1,
        vec![],
        vec![],
        0,
    )
    .unwrap();
    let drt: KeriEvent<KeyEvent> = serde_json::from_str(&raw).unwrap();
    assert_eq!(drt.event_type, EventTypeTag::Drt);
    let anchor = approve(&fx, &d.delegator, &d.delegator_last, &drt);
    fx.processor
        .process_notice(&signed(
            &drt,
            &next,
            0,
            Some(SourceSeal::new(
                anchor.data.get_sn(),
                anchor.digest().unwrap(),
            )),
        ))
        .unwrap();
    assert_eq!(state(&fx, &d.delegate).unwrap().sn, 1);

    let abandonment = event_generator::abandon(
        state(&fx, &d.delegate).unwrap(),
        vec![key(&after_next)],
        1,
        vec![],
        vec![],
        0,
        vec![],
    )
    .unwrap();
    assert_eq!(abandonment.event_type, EventTypeTag::Drt);
    let anchor = approve(&fx, &d.delegator, &anchor, &abandonment);
    fx.processor
        .process_notice(&signed(
            &abandonment,
            &after_next,
            0,
            Some(SourceSeal::new(
                anchor.data.get_sn(),
                anchor.digest().unwrap(),
            )),
        ))
        .unwrap();
    assert!(state(&fx, &d.delegate).unwrap().is_abandoned());
}

/// What a peer receives: the event serialized to CESR and parsed back. A
/// parsed `drt` carries the same data as a `rot`; only its type tag says it
/// is delegated.
fn over_the_wire(notice: Notice) -> Notice {
    use crate::{actor::parse_event_stream, event_message::signed_event_message::Message};

    let cesr = Message::Notice(notice).to_cesr().unwrap();
    match parse_event_stream(&cesr).unwrap().remove(0) {
        Message::Notice(notice) => notice,
        _ => unreachable!(),
    }
}

#[test]
fn a_received_delegated_rotation_needs_its_delegators_anchor() {
    let fx = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let d = delegation(&fx, &current, &[key(&next)]);

    let drt = abandonment(
        EventTypeTag::Drt,
        &d.delegate,
        1,
        &d.dip.digest().unwrap(),
        &next,
    );
    // No anchor: it waits for the delegator instead of being accepted.
    let unanchored = over_the_wire(signed(&drt, &next, 0, None));
    fx.processor.process_notice(&unanchored).unwrap();
    assert_eq!(state(&fx, &d.delegate).unwrap().sn, 0);

    // Anchored: the source seal survives parsing and the rotation applies.
    let anchor = approve(&fx, &d.delegator, &d.delegator_last, &drt);
    let anchored = over_the_wire(signed(
        &drt,
        &next,
        0,
        Some(SourceSeal::new(anchor.data.get_sn(), anchor.digest().unwrap())),
    ));
    fx.processor.process_notice(&anchored).unwrap();
    assert!(state(&fx, &d.delegate).unwrap().is_abandoned());
}
