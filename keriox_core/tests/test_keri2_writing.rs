//! keriox writes KERI 2.0 key events and receipts when asked to, and reads
//! back what it writes: each message goes over the wire and is accepted.

use std::sync::Arc;

use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal, SourceSeal},
        KeyEvent,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder,
        keri_version::KeriVersion,
        msg::KeriEvent,
        signature::Nontransferable,
        signed_event_message::{Message, Notice, SignedNontransferableReceipt},
        EventTypeTag,
    },
    event::receipt::Receipt,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
    signer::Signer,
};
use said::version::format::SerializationFormats;
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

fn v2() -> EventMsgBuilder {
    EventMsgBuilder::new(EventTypeTag::Icp).with_version(KeriVersion::V2)
}

/// Signs the event, sends it over the wire and processes what is read back.
fn send(fx: &Fixture, event: &KeriEvent<KeyEvent>, signer: &Signer, seal: Option<SourceSeal>) {
    let raw = String::from_utf8(event.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERICAACAAJSON"#), "{raw}");
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    let cesr = Message::Notice(Notice::Event(event.sign(
        vec![IndexedSignature::new_both_same(sig, 0)],
        None,
        seal,
    )))
    .to_cesr()
    .unwrap();
    for message in parse_event_stream(&cesr).unwrap() {
        let Message::Notice(notice) = message else {
            panic!("not a notice")
        };
        process_notice(notice, &fx.processor).unwrap();
    }
}

fn sn(fx: &Fixture, id: &IdentifierPrefix) -> Option<u64> {
    fx.storage.get_state(id).map(|state| state.sn)
}

#[test]
fn a_keri_2_kel_is_written_and_accepted() {
    let fx = setup();
    let (k0, k1, k2) = (Signer::new(), Signer::new(), Signer::new());
    let icp = v2()
        .with_keys(vec![key(&k0)])
        .with_next_keys(vec![key(&k1)])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    send(&fx, &icp, &k0, None);
    assert_eq!(sn(&fx, &id), Some(0));

    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_version(KeriVersion::V2)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&k1)])
        .with_next_keys(vec![key(&k2)])
        .build()
        .unwrap();
    // A KERI 2.0 rotation carries the configuration traits field.
    match &rot.data.event_data {
        EventData::Rot(rot) => assert_eq!(rot.config, Some(vec![])),
        other => panic!("not a rotation: {other:?}"),
    }
    send(&fx, &rot, &k1, None);
    assert_eq!(sn(&fx, &id), Some(1));

    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_version(KeriVersion::V2)
        .with_prefix(&id)
        .with_sn(2)
        .with_previous_event(&rot.digest().unwrap())
        .build()
        .unwrap();
    send(&fx, &ixn, &k1, None);
    assert_eq!(sn(&fx, &id), Some(2));

    // The stored events are served back in KERI 2.0.
    let kel = String::from_utf8(fx.storage.get_kel(&id).unwrap().unwrap()).unwrap();
    assert_eq!(kel.matches(r#"{"v":"KERICAACAAJSON"#).count(), 3, "{kel}");
}

#[test]
fn a_keri_2_delegation_is_written_and_accepted() {
    let fx = setup();
    let delegator = Signer::new();
    let delegator_icp = v2()
        .with_keys(vec![key(&delegator)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let delegator_id = delegator_icp.data.get_prefix();
    send(&fx, &delegator_icp, &delegator, None);

    let (d0, d1) = (Signer::new(), Signer::new());
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_version(KeriVersion::V2)
        .with_delegator(&delegator_id)
        .with_keys(vec![key(&d0)])
        .with_next_keys(vec![key(&d1)])
        .build()
        .unwrap();
    let id = dip.data.get_prefix();
    let drt = EventMsgBuilder::new(EventTypeTag::Drt)
        .with_version(KeriVersion::V2)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&dip.digest().unwrap())
        .with_keys(vec![key(&d1)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let seal = |event: &KeriEvent<KeyEvent>| {
        Seal::Event(EventSeal::new(
            event.data.get_prefix(),
            event.data.get_sn(),
            event.digest().unwrap(),
        ))
    };
    let anchor = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_version(KeriVersion::V2)
        .with_prefix(&delegator_id)
        .with_sn(1)
        .with_previous_event(&delegator_icp.digest().unwrap())
        .with_seal(vec![seal(&dip), seal(&drt)])
        .build()
        .unwrap();
    send(&fx, &anchor, &delegator, None);
    let source = SourceSeal::new(1, anchor.digest().unwrap());
    send(&fx, &dip, &d0, Some(source.clone()));
    send(&fx, &drt, &d1, Some(source));
    assert_eq!(sn(&fx, &id), Some(1));
}

#[test]
fn a_keri_2_receipt_is_written_and_accepted() {
    let fx = setup();
    let (current, witness) = (Signer::new(), Signer::new());
    let witness_id = BasicPrefix::Ed25519NT(witness.public_key());
    let icp = v2()
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .with_witness_list(&[witness_id.clone()])
        .with_witness_threshold(&keri_core::event::sections::threshold::SignatureThreshold::Simple(1))
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    send(&fx, &icp, &current, None);
    assert_eq!(sn(&fx, &id), None);

    let rct = Receipt::new(
        KeriVersion::V2,
        SerializationFormats::JSON,
        icp.digest().unwrap(),
        id.clone(),
        0,
    );
    let raw = String::from_utf8(rct.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERICAACAAJSON"#), "{raw}");
    let sig = SelfSigningPrefix::Ed25519Sha512(witness.sign(icp.encode().unwrap()).unwrap());
    let cesr = Message::Notice(Notice::NontransferableRct(SignedNontransferableReceipt::new(
        &rct,
        vec![Nontransferable::Couplet(vec![(witness_id, sig)])],
    )))
    .to_cesr()
    .unwrap();
    for message in parse_event_stream(&cesr).unwrap() {
        let Message::Notice(notice) = message else {
            panic!("not a notice")
        };
        process_notice(notice, &fx.processor).unwrap();
    }
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn keri_1_stays_the_default() {
    let current = Signer::new();
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    let raw = String::from_utf8(icp.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERI10JSON"#), "{raw}");
}
