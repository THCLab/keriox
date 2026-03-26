use std::fmt::{self, Display};

use crate::{database::rkyv_adapter::said_wrapper::SaidValue, prefix::IdentifierPrefix};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
#[serde(untagged)]
pub enum Seal {
    Location(LocationSeal),
    Event(EventSeal),
    Digest(DigestSeal),
    Root(RootSeal),
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct DigestSeal {
    #[serde(rename = "d")]
    dig: SaidValue,
}

impl DigestSeal {
    pub fn new(said: SelfAddressingIdentifier) -> Self {
        Self { dig: said.into() }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct RootSeal {
    #[serde(rename = "rd")]
    tree_root: SaidValue,
}

#[derive(
    Serialize,
    Deserialize,
    // Debug,
    Clone,
    Default,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct EventSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "d")]
    event_digest: SaidValue,
}

impl EventSeal {
    pub fn new(
        identifier: IdentifierPrefix,
        sn: u64,
        event_digest: SelfAddressingIdentifier,
    ) -> Self {
        Self {
            prefix: identifier,
            sn,
            event_digest: event_digest.into(),
        }
    }

    pub fn event_digest(&self) -> SelfAddressingIdentifier {
        self.event_digest.said.clone()
    }
}

impl Display for EventSeal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", serde_json::to_string(self).unwrap())
    }
}

impl fmt::Debug for EventSeal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Just forward to Display
        write!(f, "{}", self)
    }
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Default,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct LocationSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "t")]
    pub ilk: String,

    #[serde(rename = "p")]
    prior_digest: SaidValue,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DelegatingEventSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "d")]
    pub commitment: SelfAddressingIdentifier,
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]

pub struct SourceSeal {
    pub sn: u64,
    pub digest: SaidValue,
}

impl SourceSeal {
    pub fn new(sn: u64, digest: SelfAddressingIdentifier) -> Self {
        Self {
            sn,
            digest: digest.into(),
        }
    }
}

#[test]
fn test_seal_deserialization() {
    // Event seal
    let seal_str = r#"{"i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","d":"EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"}"#;
    let seal: Seal = serde_json::from_str(seal_str).unwrap();
    assert!(matches!(seal, Seal::Event(_)));
    assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);

    // Location seal
    let seal_str = r#"{"i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","t":"ixn","p":"EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"}"#;
    let seal: Seal = serde_json::from_str(seal_str).unwrap();
    assert!(matches!(seal, Seal::Location(_)));
    assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);

    // Digest seal
    let seal_str = r#"{"d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"}"#;
    let seal: Seal = serde_json::from_str(seal_str).unwrap();
    assert!(matches!(seal, Seal::Digest(_)));
    assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);
}
