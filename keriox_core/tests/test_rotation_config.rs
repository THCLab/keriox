//! The configuration traits field `c` of rotations. KERI 2.0 makes it
//! REQUIRED in `rot` and `drt` bodies, between `ba` and `a`; KERI 1.0
//! bodies have no `c`. Traits that may only appear in an inception (`EO`,
//! `DND`, `DID`) are not allowed in a rotation.

use std::sync::Arc;

use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    error::Error,
    event::{event_data::EventData, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder,
        msg::KeriEvent,
        signed_event_message::{Message, Notice},
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use said::{
    derivation::HashFunctionCode,
    sad::SAD,
    version::{format::SerializationFormats, SerializationInfo},
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

fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer) -> Notice {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None))
}

/// Sets the rotation's `c`, switches the body to KERI `major`.0 and
/// recomputes its size and SAID.
fn reshape(
    mut event: KeriEvent<KeyEvent>,
    major: u8,
    config: Option<Vec<&str>>,
) -> KeriEvent<KeyEvent> {
    match &mut event.data.event_data {
        EventData::Rot(rot) | EventData::Drt(rot) => {
            rot.config = config.map(|c| c.into_iter().map(String::from).collect())
        }
        _ => unreachable!(),
    }
    let mut info =
        SerializationInfo::new_empty("KERI".to_string(), major, 0, SerializationFormats::JSON);
    if major == 2 {
        info.genus_version = Some((2, 0));
    }
    event.serialization_info = info;
    let code = HashFunctionCode::Blake3_256;
    event.serialization_info.size = event
        .derivation_data(&code, &SerializationFormats::JSON)
        .unwrap()
        .len();
    event
        .compute_digest(&code, &SerializationFormats::JSON)
        .unwrap();
    event
}

/// An inception, and a rotation of it (KERI 1.0, no `c`) signed by `next`.
fn kel(fx: &Fixture) -> (IdentifierPrefix, KeriEvent<KeyEvent>, Signer) {
    let (current, next) = (Signer::new(), Signer::new());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&current)])
        .with_next_keys(vec![key(&next)])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    process_notice(signed(&icp, &current), &fx.processor).unwrap();
    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&next)])
        .with_next_keys(vec![key(&Signer::new())])
        .build()
        .unwrap();
    (id, rot, next)
}

fn sn(fx: &Fixture, id: &IdentifierPrefix) -> Option<u64> {
    fx.storage.get_state(id).map(|state| state.sn)
}

#[test]
fn a_keri_2_rotation_with_c_is_read_and_accepted() {
    let fx = setup();
    let (id, rot, next) = kel(&fx);
    let rot = reshape(rot, 2, Some(vec![]));

    let raw = String::from_utf8(rot.encode().unwrap()).unwrap();
    assert!(raw.starts_with(r#"{"v":"KERICAACAAJSON"#), "{raw}");
    assert!(raw.contains(r#""ba":[],"c":[],"a":[]"#), "{raw}");

    // Read back from the wire, byte for byte.
    let notice = signed(&rot, &next);
    let cesr = Message::Notice(notice).to_cesr().unwrap();
    let parsed = parse_event_stream(&cesr).unwrap().remove(0);
    let Message::Notice(parsed) = parsed else {
        unreachable!()
    };
    process_notice(parsed, &fx.processor).unwrap();
    assert_eq!(sn(&fx, &id), Some(1));
}

#[test]
fn a_keri_1_rotation_has_no_c() {
    let fx = setup();
    let (id, rot, next) = kel(&fx);
    let raw = String::from_utf8(rot.encode().unwrap()).unwrap();
    assert!(!raw.contains(r#""c":"#), "{raw}");

    let with_c = reshape(rot, 1, Some(vec![]));
    assert!(matches!(
        process_notice(signed(&with_c, &next), &fx.processor),
        Err(Error::SemanticError(_))
    ));
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn a_keri_2_rotation_without_c_is_refused() {
    let fx = setup();
    let (id, rot, next) = kel(&fx);
    let rot = reshape(rot, 2, None);
    assert!(matches!(
        process_notice(signed(&rot, &next), &fx.processor),
        Err(Error::SemanticError(_))
    ));
    assert_eq!(sn(&fx, &id), Some(0));
}

#[test]
fn a_rotation_cannot_carry_inception_only_traits() {
    for trait_ in ["EO", "DND", "DID"] {
        let fx = setup();
        let (id, rot, next) = kel(&fx);
        let rot = reshape(rot, 2, Some(vec![trait_]));
        assert!(
            matches!(
                process_notice(signed(&rot, &next), &fx.processor),
                Err(Error::ConfigTraitViolation(_))
            ),
            "{trait_}"
        );
        assert_eq!(sn(&fx, &id), Some(0));
    }
}
