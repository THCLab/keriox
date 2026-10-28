//! ACDC 2.0 state registries (TELs): the issuance and revocation state of
//! ACDCs, kept as a chain of registry events, each committed to by a seal in
//! the Issuer's KEL. There are no registry backers: the Issuer's KEL, which
//! its witnesses already back, is the proof.

pub mod blind;
pub mod event;
pub mod issuer;
pub mod store;
pub mod validator;
pub mod verify;

pub use blind::{Blinding, Salt, StateBlock};
pub use event::{RegistryIlk, RegistryMessage};
pub use issuer::{Disclosure, Pending, RegistryIssuer};
pub use store::{MemoryRegistryStore, RegistryStore};
pub use validator::{AbandonedIssuer, Evidence, Policy, Validator, Verdict};
pub use verify::{verify, AcdcBinding, Binding, RegistryState};

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum RegistryError {
    /// The message or block is not a well-formed registry message.
    #[error("registry message: {0}")]
    Format(String),
    /// The events do not chain from the inception.
    #[error("registry chain: {0}")]
    Chain(String),
    /// No seal in the Issuer's KEL commits to the event. Retryable: the
    /// anchor may still be on its way.
    #[error("no anchor in the Issuer's KEL for registry event {0}")]
    MissingAnchor(said::SelfAddressingIdentifier),
    /// Two distinct anchored events at one position.
    #[error("registry duplicity: {0}")]
    Duplicity(String),
    /// The Issuer anchored a later update than the ones presented.
    #[error("stale registry: {0}")]
    Stale(String),
    /// A disclosed blinded state does not match, or none was disclosed.
    #[error("blinded state: {0}")]
    Blind(String),
    /// The registry state does not bind the presented ACDC.
    #[error("ACDC binding: {0}")]
    Binding(String),
    /// The Validator's policy rejects credentials of an Issuer that
    /// abandoned its identifier.
    #[error("issuer {0} abandoned its identifier")]
    AbandonedIssuer(keri_core::prefix::IdentifierPrefix),
    /// The store failed, or holds what cannot be read back.
    #[error("registry store: {0}")]
    Storage(String),
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
        assert!(messages[0].issuer().is_some());
        for (message, raw) in messages.iter().zip(&raws) {
            assert_eq!(message.encode(), raw.as_bytes());
        }
        let regid = messages[0].said().unwrap();
        assert_eq!(messages[1].registry().unwrap(), regid);
        assert_eq!(
            messages[2].prior().unwrap().unwrap(),
            messages[1].said().unwrap()
        );
        assert_eq!(messages[2].sn(), 2);
    }

    /// keriox builds the same `rip` and `bup` keripy wrote from the same
    /// fields, SAIDs and sizes included.
    #[test]
    fn registry_events_are_built_as_keripy_builds_them() {
        let vectors = keripy();
        let issuer = vectors["issuer"].as_str().unwrap().parse().unwrap();
        let rip = RegistryMessage::incept(
            &issuer,
            "0ABrZXJpc3BlY3dvcmtyYXcw",
            "2026-01-01T00:00:00.000000+00:00",
        )
        .unwrap();
        assert_eq!(rip.encode(), vectors["rip"].as_str().unwrap().as_bytes());
        let first = &vectors["updates"][0];
        let blid = first["blid"].as_str().unwrap().parse().unwrap();
        let bup =
            RegistryMessage::blindable_update(&rip, &blid, "2026-01-02T00:00:00.000000+00:00")
                .unwrap();
        assert_eq!(bup.encode(), first["bup"].as_str().unwrap().as_bytes());
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
            format!("{rip} "),
        ] {
            assert!(RegistryMessage::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }
}
