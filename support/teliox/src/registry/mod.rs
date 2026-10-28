//! ACDC 2.0 state registries (TELs): the issuance and revocation state of
//! ACDCs, kept as a chain of registry events, each committed to by a seal in
//! the Issuer's KEL. There are no registry backers: the Issuer's KEL, which
//! its witnesses already back, is the proof.

pub mod blind;
pub mod event;

pub use blind::{BlindedState, Salt};
pub use event::{
    BlindableUpdate, Inception, RegistryEvent, RegistryIlk, RegistryMessage, Update,
};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum RegistryError {
    /// The message or block is not a well-formed registry message.
    #[error("registry message: {0}")]
    Format(String),
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::RegistryMessage;

    /// Registry events keripy 424a50c wrote, with their blinded state
    /// blocks (test-vectors/acdc/registry/gen_keripy.py).
    pub(crate) fn keripy() -> Value {
        serde_json::from_str(include_str!(
            "../../../../test-vectors/acdc/registry/keripy.json"
        ))
        .unwrap()
    }

    /// keripy's registry events read as their types and are written back
    /// byte for byte.
    #[test]
    fn keripy_registry_events_round_trip() {
        let vectors = keripy();
        let mut raws = vec![vectors["rip"].as_str().unwrap().to_string()];
        for update in vectors["updates"].as_array().unwrap() {
            raws.push(update["bup"].as_str().unwrap().to_string());
        }
        let messages: Vec<RegistryMessage> = raws
            .iter()
            .map(|raw| RegistryMessage::parse(raw.as_bytes()).unwrap())
            .collect();
        assert!(matches!(messages[0], RegistryMessage::Inception(_)));
        assert!(matches!(messages[1], RegistryMessage::Blindable(_)));
        for (message, raw) in messages.iter().zip(&raws) {
            assert_eq!(message.encode().unwrap(), raw.as_bytes());
        }
        let regid = messages[0].said().unwrap();
        assert_eq!(messages[1].registry().unwrap(), regid);
        assert_eq!(messages[2].prior(), Some(&messages[1].said().unwrap()));
        assert_eq!(messages[2].sn(), 2);
    }

    /// keriox builds the same `rip` and `bup` keripy wrote from the same
    /// fields, SAIDs and sizes included.
    #[test]
    fn registry_events_are_built_as_keripy_builds_them() {
        use super::event::{build, BlindableUpdate, Inception};

        let vectors = keripy();
        let time = |text: &str| chrono::DateTime::parse_from_rfc3339(text).unwrap();
        let rip = build(Inception {
            nonce: "0ABrZXJpc3BlY3dvcmtyYXcw".into(),
            issuer: vectors["issuer"].as_str().unwrap().parse().unwrap(),
            sn: 0,
            timestamp: time("2026-01-01T00:00:00+00:00"),
        });
        assert_eq!(
            String::from_utf8(rip.encode().unwrap()).unwrap(),
            vectors["rip"].as_str().unwrap()
        );
        let first = &vectors["updates"][0];
        let bup = build(BlindableUpdate {
            registry: rip.digest().unwrap(),
            sn: 1,
            prior: rip.digest().unwrap(),
            timestamp: time("2026-01-02T00:00:00+00:00"),
            blid: first["blid"].as_str().unwrap().parse().unwrap(),
        });
        assert_eq!(
            String::from_utf8(bup.encode().unwrap()).unwrap(),
            first["bup"].as_str().unwrap()
        );
    }

    /// A body that is not a registry event, or one changed after its SAID
    /// was computed, is refused.
    #[test]
    fn a_malformed_registry_event_is_refused() {
        let vectors = keripy();
        let rip = vectors["rip"].as_str().unwrap();
        for bad in [
            rip.replace("\"t\":\"rip\"", "\"t\":\"icp\""),
            rip.replace("\"n\":\"0\"", "\"n\":\"00\""),
            rip.replace("2026-01-01", "2026-01-02"),
            rip.replace("ACDCCAACAA", "KERICAACAA"),
        ] {
            assert!(RegistryMessage::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
