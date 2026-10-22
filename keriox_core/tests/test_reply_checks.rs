//! Checks on endpoint replies (`/loc/scheme`) from the KERI specification:
//! - a signature without a reference to key state (a non-transferable
//!   couple) is only valid for an AID with a non-transferable code, whose key
//!   state is fixed;
//! - a reply is a KERI message: its version string names KERI;
//! - BADA accepts an update only when its date-time is later than the
//!   prior's.
#![cfg(feature = "oobi-manager")]

use std::sync::Arc;

use chrono::DateTime;
use keri_core::{
    actor::{parse_event_stream, process_reply},
    database::redb::RedbDatabase,
    error::Error,
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Scheme},
    oobi_manager::{OobiManager, RedbOobiManager},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::Signer,
};
use said::{derivation::HashFunctionCode, sad::SAD, version::format::SerializationFormats};
use tempfile::NamedTempFile;
use url::Url;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    oobis: RedbOobiManager,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), None),
        storage: EventStorage::new(db.clone()),
        oobis: OobiManager::new(db).unwrap(),
    }
}

/// A `/loc/scheme` reply for `eid` dated `dt`, in the `protocol` given by
/// its version string.
fn loc_scheme(eid: &BasicPrefix, url: &str, dt: &str, protocol: &str) -> ReplyEvent {
    let mut rpy = ReplyEvent::new_reply(
        ReplyRoute::LocScheme(LocationScheme::new(
            IdentifierPrefix::Basic(eid.clone()),
            Scheme::Http,
            Url::parse(url).unwrap(),
        )),
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
    );
    rpy.data.timestamp = DateTime::parse_from_rfc3339(dt).unwrap();
    rpy.serialization_info.protocol_code = protocol.to_string();
    let code = HashFunctionCode::Blake3_256;
    rpy.serialization_info.size = rpy
        .derivation_data(&code, &SerializationFormats::JSON)
        .unwrap()
        .len();
    rpy.compute_digest(&code, &SerializationFormats::JSON)
        .unwrap();
    rpy
}

/// Signs the reply with `signer`'s couple and sends it through the wire
/// format.
fn send(fx: &Fixture, rpy: ReplyEvent, signer: &Signer, eid: &BasicPrefix) -> Result<(), Error> {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(rpy.encode().unwrap()).unwrap());
    let cesr = Message::Op(Op::Reply(SignedReply::new_nontrans(rpy, eid.clone(), sig)))
        .to_cesr()
        .unwrap();
    match parse_event_stream(&cesr)
        .map_err(|e| Error::SemanticError(e.to_string()))?
        .remove(0)
    {
        Message::Op(Op::Reply(rpy)) => process_reply(rpy, &fx.oobis, &fx.processor, &fx.storage),
        other => panic!("not a reply: {other:?}"),
    }
}

fn urls(fx: &Fixture, eid: &BasicPrefix) -> Vec<String> {
    fx.oobis
        .get_loc_scheme(&IdentifierPrefix::Basic(eid.clone()))
        .unwrap()
        .into_iter()
        .map(|rpy| match rpy.get_route() {
            ReplyRoute::LocScheme(loc) => loc.url.to_string(),
            other => panic!("not a location: {other:?}"),
        })
        .collect()
}

const DT: &str = "2020-08-21T17:52:16.000000+00:00";

#[test]
fn a_non_transferable_key_signs_its_own_location() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    send(
        &fx,
        loc_scheme(&eid, "http://a/", DT, "KERI"),
        &signer,
        &eid,
    )
    .unwrap();
    assert_eq!(urls(&fx, &eid), vec!["http://a/"]);
}

#[test]
fn a_transferable_key_cannot_sign_with_a_non_transferable_couple() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519(signer.public_key());
    assert!(send(
        &fx,
        loc_scheme(&eid, "http://a/", DT, "KERI"),
        &signer,
        &eid
    )
    .is_err());
    assert!(urls(&fx, &eid).is_empty());
}

#[test]
fn a_reply_that_is_not_a_keri_message_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    assert!(send(
        &fx,
        loc_scheme(&eid, "http://a/", DT, "ACDC"),
        &signer,
        &eid
    )
    .is_err());
    assert!(urls(&fx, &eid).is_empty());
}

#[test]
fn an_update_needs_a_later_date_time() {
    let fx = setup();
    let signer = Signer::new();
    let eid = BasicPrefix::Ed25519NT(signer.public_key());
    let first = loc_scheme(&eid, "http://a/", DT, "KERI");
    send(&fx, first.clone(), &signer, &eid).unwrap();

    // The same reply again changes nothing and is not an error.
    send(&fx, first, &signer, &eid).unwrap();
    // A different reply with the same date-time is refused.
    assert!(send(
        &fx,
        loc_scheme(&eid, "http://evil/", DT, "KERI"),
        &signer,
        &eid
    )
    .is_err());
    assert_eq!(urls(&fx, &eid), vec!["http://a/"]);

    send(
        &fx,
        loc_scheme(
            &eid,
            "http://b/",
            "2020-08-21T17:52:17.000000+00:00",
            "KERI",
        ),
        &signer,
        &eid,
    )
    .unwrap();
    assert_eq!(urls(&fx, &eid), vec!["http://b/"]);
}
