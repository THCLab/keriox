//! Key events and key states are stored archived with rkyv, so a change to
//! their types must leave the archived layout of existing data readable.
//! The fixture holds events (weighted thresholds, every seal type keriox
//! had) and a key state archived by keriox before the KERI 2.0 seal types
//! and nested thresholds were added; they must still read back as written.

use keri_core::{
    event::KeyEvent,
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
    },
    state::IdentifierState,
};
use rkyv::{rancor::Failure, util::AlignedVec};

fn bytes(hex: &str) -> AlignedVec {
    let mut aligned = AlignedVec::<16>::new();
    for i in (0..hex.len()).step_by(2) {
        aligned.push(u8::from_str_radix(&hex[i..i + 2], 16).unwrap());
    }
    aligned
}

#[test]
fn events_and_key_states_stored_before_keri_2_read_back() {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/stored_layout_1.json")).unwrap();
    for event in fixture["events"].as_array().unwrap() {
        let stored: KeriEvent<KeyEvent> =
            rkyv::from_bytes::<_, Failure>(&bytes(event["rkyv"].as_str().unwrap())).unwrap();
        let body = event["body"].as_str().unwrap();
        assert_eq!(String::from_utf8(stored.encode().unwrap()).unwrap(), body);
        // The body itself still parses to the same event.
        match parse_event_type(body.as_bytes()).unwrap() {
            EventType::KeyEvent(parsed) => assert_eq!(parsed, stored),
            _ => panic!("not a key event"),
        }
    }
    let state: IdentifierState =
        rkyv::from_bytes::<_, Failure>(&bytes(fixture["state"]["rkyv"].as_str().unwrap())).unwrap();
    assert_eq!(
        serde_json::to_value(&state).unwrap(),
        fixture["state"]["json"]
    );
}
