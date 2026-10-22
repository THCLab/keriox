//! The current key list and signing threshold of establishment events, as
//! the KERI specification and KERIpy require: the key list must not be
//! empty, the threshold may not need more keys (nor list more weights) than
//! the list has, and an event without a single controller signature is
//! dropped rather than escrowed or accepted.

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
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
    signer::Signer,
};
use tempfile::NamedTempFile;

fn setup() -> (
    NamedTempFile,
    BasicProcessor<RedbDatabase>,
    EventStorage<RedbDatabase>,
) {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    (
        path,
        BasicProcessor::new(db.clone(), Some(bus)),
        EventStorage::new(db),
    )
}

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn signed_by(event: &KeriEvent<KeyEvent>, signers: &[&Signer]) -> Notice {
    let sigs = signers
        .iter()
        .enumerate()
        .map(|(i, signer)| {
            let sig =
                SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
            IndexedSignature::new_both_same(sig, i as u16)
        })
        .collect();
    Notice::Event(event.sign(sigs, None, None))
}

fn sn(storage: &EventStorage<RedbDatabase>, id: &IdentifierPrefix) -> Option<u64> {
    storage.get_state(id).map(|state| state.sn)
}

/// Current key lists and thresholds that do not fit together.
fn unsound_current_keys(a: &Signer, b: &Signer) -> Vec<(Vec<BasicPrefix>, SignatureThreshold)> {
    vec![
        (vec![], SignatureThreshold::Simple(0)),
        (vec![key(a)], SignatureThreshold::Simple(2)),
        (
            vec![key(a), key(b)],
            SignatureThreshold::single_weighted(vec![(1, 2), (1, 2), (1, 2)]),
        ),
    ]
}

#[test]
fn inception_with_unsound_current_keys_is_refused() {
    let (a, b) = (Signer::new(), Signer::new());
    for (keys, threshold) in unsound_current_keys(&a, &b) {
        let (_path, processor, storage) = setup();
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(keys.clone())
            .with_threshold(&threshold)
            .with_next_keys(vec![key(&Signer::new())])
            .build()
            .unwrap();
        // At least one signature, so the event is not dropped as unsigned
        // before its keys are checked.
        let signers: Vec<&Signer> = [&a, &b].into_iter().take(keys.len().max(1)).collect();
        assert!(
            matches!(
                process_notice(signed_by(&icp, &signers), &processor),
                Err(Error::SemanticError(_))
            ),
            "k={keys:?} kt={threshold:?} was not refused"
        );
        assert_eq!(sn(&storage, &icp.data.get_prefix()), None);
    }
}

#[test]
fn rotation_with_unsound_current_keys_is_refused() {
    let (a, b) = (Signer::new(), Signer::new());
    for (keys, threshold) in unsound_current_keys(&a, &b) {
        let (_path, processor, storage) = setup();
        let current = Signer::new();
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(&current)])
            .with_next_keys(vec![key(&a), key(&b)])
            .with_next_threshold(&SignatureThreshold::Simple(1))
            .build()
            .unwrap();
        let id = icp.data.get_prefix();
        process_notice(signed_by(&icp, &[&current]), &processor).unwrap();

        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&id)
            .with_sn(1)
            .with_previous_event(&icp.digest().unwrap())
            .with_keys(keys.clone())
            .with_threshold(&threshold)
            .with_next_keys(vec![key(&Signer::new())])
            .build()
            .unwrap();
        // At least one signature, so the event is not dropped as unsigned
        // before its keys are checked.
        let signers: Vec<&Signer> = [&a, &b].into_iter().take(keys.len().max(1)).collect();
        assert!(
            matches!(
                process_notice(signed_by(&rot, &signers), &processor),
                Err(Error::SemanticError(_))
            ),
            "k={keys:?} kt={threshold:?} was not refused"
        );
        assert_eq!(sn(&storage, &id), Some(0));
    }
}

#[test]
fn an_unsigned_event_is_dropped() {
    let (_path, processor, storage) = setup();
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();

    assert!(matches!(
        process_notice(signed_by(&icp, &[]), &processor),
        Err(Error::MissingSignatures)
    ));
    assert_eq!(sn(&storage, &id), None);

    // Dropped, not escrowed: the signed event is accepted on its own.
    process_notice(signed_by(&icp, &[&current]), &processor).unwrap();
    assert_eq!(sn(&storage, &id), Some(0));
}

#[test]
fn a_zero_signing_threshold_still_needs_a_signature() {
    // The spec allows kt=0, which any signature set meets, but an event
    // must still carry at least one verifiable controller signature.
    let (_path, processor, storage) = setup();
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_threshold(&SignatureThreshold::Simple(0))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();

    assert!(matches!(
        process_notice(signed_by(&icp, &[]), &processor),
        Err(Error::MissingSignatures)
    ));
    assert_eq!(sn(&storage, &id), None);

    process_notice(signed_by(&icp, &[&current]), &processor).unwrap();
    assert_eq!(sn(&storage, &id), Some(0));
}

#[test]
fn a_threshold_fitting_its_keys_is_accepted() {
    let (_path, processor, storage) = setup();
    let (a, b) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&a), key(&b)])
        .with_threshold(&SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]))
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    process_notice(signed_by(&icp, &[&a, &b]), &processor).unwrap();
    assert_eq!(sn(&storage, &icp.data.get_prefix()), Some(0));
}

/// One key cannot count twice towards a threshold: the specification counts
/// M of the N keys of a key set.
#[test]
fn a_repeated_signature_index_counts_once() {
    assert!(SignatureThreshold::Simple(2)
        .enough_signatures(&[0, 0])
        .is_err());
    assert!(SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)])
        .enough_signatures(&[0, 0])
        .is_err());
    assert!(SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2)], vec![(1, 1)]])
        .enough_signatures(&[0, 0, 2])
        .is_err());
    assert!(SignatureThreshold::Simple(2)
        .enough_signatures(&[0, 1])
        .is_ok());
}

#[test]
fn a_key_listed_twice_is_refused() {
    let (a, next) = (Signer::new(), Signer::new());
    let (_path, processor, storage) = setup();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&a), key(&a)])
        .with_threshold(&SignatureThreshold::Simple(2))
        .with_next_keys(vec![key(&next)])
        .build()
        .unwrap();
    // One key signing at both positions would meet kt=2 on its own.
    assert!(matches!(
        process_notice(signed_by(&icp, &[&a, &a]), &processor),
        Err(Error::SemanticError(_))
    ));
    assert_eq!(sn(&storage, &icp.data.get_prefix()), None);
}

#[test]
fn a_next_key_committed_twice_is_refused() {
    let (current, next) = (Signer::new(), Signer::new());
    let (_path, processor, storage) = setup();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&next), key(&next)])
        .with_next_threshold(&SignatureThreshold::Simple(2))
        .build()
        .unwrap();
    assert!(matches!(
        process_notice(signed_by(&icp, &[&current]), &processor),
        Err(Error::SemanticError(_))
    ));
    assert_eq!(sn(&storage, &icp.data.get_prefix()), None);
}

/// The takeover the review found: with n=[H(K1), H(K2)] and nt=2, whoever
/// holds K1 alone listed it twice and signed at both positions, so its
/// single prior-next position counted twice.
#[test]
fn one_exposed_next_key_cannot_meet_the_prior_next_threshold_twice() {
    for (prior_next, kt) in [
        (SignatureThreshold::Simple(2), SignatureThreshold::Simple(1)),
        (
            SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]),
            SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]),
        ),
    ] {
        let (_path, processor, storage) = setup();
        let (current, k1, k2) = (Signer::new(), Signer::new(), Signer::new());
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(&current)])
            .with_next_keys(vec![key(&k1), key(&k2)])
            .with_next_threshold(&prior_next)
            .build()
            .unwrap();
        let id = icp.data.get_prefix();
        process_notice(signed_by(&icp, &[&current]), &processor).unwrap();

        let rot = EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&id)
            .with_sn(1)
            .with_previous_event(&icp.digest().unwrap())
            .with_keys(vec![key(&k1), key(&k1)])
            .with_threshold(&kt)
            .with_next_keys(vec![key(&Signer::new())])
            .build()
            .unwrap();
        let sig = SelfSigningPrefix::Ed25519Sha512(k1.sign(rot.encode().unwrap()).unwrap());
        let forged = rot.sign(
            vec![
                IndexedSignature::new_both_diffrent(sig.clone(), 0, 0),
                IndexedSignature::new_both_diffrent(sig, 1, 0),
            ],
            None,
            None,
        );
        let _ = process_notice(Notice::Event(forged), &processor);
        assert_eq!(sn(&storage, &id), Some(0), "nt={prior_next:?}");
    }
}
