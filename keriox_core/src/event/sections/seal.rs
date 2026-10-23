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
/// A seal anchored in an event's `a` field. Each kind is told apart by its
/// exact set of fields, so a seal with a malformed or extra field is refused
/// rather than read as another kind.
///
/// The stored (rkyv) layout of existing seals must not change: new kinds go
/// at the end and must not be larger than `Location`.
pub enum Seal {
    Location(LocationSeal),
    Event(EventSeal),
    Digest(DigestSeal),
    Root(RootSeal),
    /// Source event seal `{s, d}`.
    Source(SourceEventSeal),
    /// Latest establishment event seal `{i}`.
    LatestEstablishment(LatestEstablishmentSeal),
    /// Registrar backer seal `{bi, d}`.
    RegistrarBacker(RegistrarBackerSeal),
    /// Typed digest seal `{t, d}`.
    Typed(TypedDigestSeal),
}

/// A source event seal: the sn and SAID of an event of the KEL it is
/// anchored in.
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
#[serde(deny_unknown_fields)]
pub struct SourceEventSeal {
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(rename = "d")]
    pub digest: SaidValue,
}

/// A latest establishment event seal: whatever the latest establishment
/// event of `prefix` is when the seal is read.
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
#[serde(deny_unknown_fields)]
pub struct LatestEstablishmentSeal {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,
}

/// A registrar backer seal: the backer identifier and the SAID of its
/// metadata.
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
#[serde(deny_unknown_fields)]
pub struct RegistrarBackerSeal {
    #[serde(rename = "bi")]
    pub backer: IdentifierPrefix,

    #[serde(rename = "d")]
    pub digest: SaidValue,
}

/// A typed digest seal: a SAID with the type of what it digests.
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
#[serde(deny_unknown_fields)]
pub struct TypedDigestSeal {
    #[serde(rename = "t")]
    pub kind: String,

    #[serde(rename = "d")]
    pub digest: SaidValue,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

#[test]
fn keri_2_seal_types_read_as_themselves() {
    let cases = [
        (
            r#"{"s":"3","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"}"#,
            "source",
        ),
        (
            r#"{"i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"}"#,
            "latest",
        ),
        (
            r#"{"bi":"BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"}"#,
            "registrar",
        ),
        (
            r#"{"t":"acdc","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen"}"#,
            "typed",
        ),
    ];
    for (seal_str, kind) in cases {
        let seal: Seal = serde_json::from_str(seal_str).unwrap();
        let matches = match kind {
            "source" => matches!(seal, Seal::Source(_)),
            "latest" => matches!(seal, Seal::LatestEstablishment(_)),
            "registrar" => matches!(seal, Seal::RegistrarBacker(_)),
            _ => matches!(seal, Seal::Typed(_)),
        };
        assert!(matches, "{seal_str} read as {seal:?}");
        assert_eq!(serde_json::to_string(&seal).unwrap(), seal_str);
    }
}

#[test]
fn a_seal_with_a_malformed_field_is_refused_rather_than_read_as_another_type() {
    // An event seal whose i is not an identifier must not read as a digest
    // seal that drops i and s.
    let seal_str = r#"{"i":"'EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur'","s":"1","d":"EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"}"#;
    assert!(serde_json::from_str::<Seal>(seal_str).is_err());
    // Nor a digest seal with an extra field.
    let seal_str = r#"{"d":"EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","x":"y"}"#;
    assert!(serde_json::from_str::<Seal>(seal_str).is_err());
}
