//! "A single delegating event may perform multiple delegation operations,
//! one for each delegation seal" (KERI specification). Every delegated
//! event waiting for such an event is accepted once it arrives.

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

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer, seal: Option<SourceSeal>) -> Notice {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, seal))
}

fn seal_of(event: &KeriEvent<KeyEvent>) -> Seal {
    Seal::Event(EventSeal::new(
        event.data.get_prefix(),
        event.data.get_sn(),
        event.digest().unwrap(),
    ))
}

#[test]
fn every_delegation_anchored_by_one_event_is_accepted() {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    let processor = BasicProcessor::new(db.clone(), Some(bus));
    let storage = EventStorage::new(db);
    let sn = |id: &IdentifierPrefix| storage.get_state(id).map(|state| state.sn);

    let delegator = Signer::new();
    let delegator_icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&delegator)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let delegator_id = delegator_icp.data.get_prefix();
    process_notice(signed(&delegator_icp, &delegator, None), &processor).unwrap();

    let delegates: Vec<(Signer, KeriEvent<KeyEvent>)> = (0..3)
        .map(|_| {
            let signer = Signer::new();
            let dip = EventMsgBuilder::new(EventTypeTag::Dip)
                .with_delegator(&delegator_id)
                .with_keys(vec![key(&signer)])
                .with_next_keys(vec![key(&Signer::new())])
                .build()
                .unwrap();
            (signer, dip)
        })
        .collect();

    let anchor = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&delegator_id)
        .with_sn(1)
        .with_previous_event(&delegator_icp.digest().unwrap())
        .with_seal(delegates.iter().map(|(_, dip)| seal_of(dip)).collect())
        .build()
        .unwrap();

    // The delegated inceptions arrive first and wait for the anchor.
    for (signer, dip) in &delegates {
        process_notice(
            signed(dip, signer, Some(SourceSeal::new(1, anchor.digest().unwrap()))),
            &processor,
        )
        .unwrap();
        assert_eq!(sn(&dip.data.get_prefix()), None);
    }

    process_notice(signed(&anchor, &delegator, None), &processor).unwrap();

    for (_, dip) in &delegates {
        assert_eq!(sn(&dip.data.get_prefix()), Some(0), "{}", dip.data.get_prefix());
    }
}
