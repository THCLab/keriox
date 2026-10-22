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
