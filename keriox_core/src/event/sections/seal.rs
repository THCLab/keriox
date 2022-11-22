use crate::{prefix::IdentifierPrefix, sai::SelfAddressingPrefix};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum Seal {
    Location(LocationSeal),
    Event(EventSeal),
    Digest(DigestSeal),
    Root(RootSeal),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DigestSeal {
    #[serde(rename = "d")]
    pub dig: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RootSeal {
    #[serde(rename = "rd")]
    pub tree_root: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct EventSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "d")]
    pub event_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct LocationSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "t")]
    pub ilk: String,

    #[serde(rename = "p")]
    pub prior_digest: SelfAddressingPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct DelegatingEventSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "d")]
    pub commitment: SelfAddressingPrefix,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceSeal {
    pub sn: u64,
    pub digest: SelfAddressingPrefix,
}

impl SourceSeal {
    pub fn new(sn: u64, digest: SelfAddressingPrefix) -> Self {
        Self { sn, digest }
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
