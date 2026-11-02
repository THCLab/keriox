//! IPEX, the Issuance and Presentation Exchange of the ACDC specification,
//! in the shape keripy writes it: a Discloser's `/ipex/grant` discloses an
//! ACDC, nested in the exchange's attachments with the blinded state block
//! of its registry, and the Disclosee's `/ipex/admit` acknowledges it.
//!
//! A grant names no registry events; keripy's Disclosee takes them from its
//! own copy of the registry. Nothing here serves registries, so the
//! Discloser sends the registry events ahead of the grant, as plain messages
//! of the same stream ([`grant_stream`]), and the Disclosee reads both back
//! as a [`Presentation`] ([`parse_grant_stream`]).

use acdc::Acdc;
use cesrox::payload::Payload;
use chrono::{DateTime, FixedOffset, Utc};
use keri_core::{
    database::EventDatabase,
    event_message::{
        cesr_adapter::{parse_cesr_stream_many, CesrMessage, EventType},
        field_map::{FieldMap, FieldValue},
        keri_version::KeriVersion,
        msg::KeriEvent,
        signature::{get_signatures, signatures_into_groups, Signature},
        timestamped::Timestamped,
    },
    exchange::{Exchange, ExchangeBody, ExchangeMessage},
    prefix::IdentifierPrefix,
    processor::{event_storage::EventStorage, validator::EventValidator},
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    version::format::SerializationFormats,
    SelfAddressingIdentifier,
};

use crate::registry::{Disclosure, Presentation, RegistryError, RegistryMessage, Salt, StateBlock};

/// The route of a grant.
pub const GRANT: &str = "/ipex/grant";
/// The route of an admit.
pub const ADMIT: &str = "/ipex/admit";

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum IpexError {
    /// Not a well-formed IPEX message.
    #[error("IPEX message: {0}")]
    Format(String),
    /// A signature does not verify, or the sender did not sign.
    #[error("IPEX signature: {0}")]
    Signature(String),
    /// The sender's key state is not known here yet. Retryable.
    #[error("unknown IPEX sender {0}")]
    UnknownSender(IdentifierPrefix),
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

fn format(e: impl std::fmt::Display) -> IpexError {
    IpexError::Format(e.to_string())
}

fn text(value: &str) -> FieldValue {
    FieldValue::String(value.to_string())
}

/// An exchange from `sender` to `recipient` in transaction `transaction`,
/// following `prior`: every field of the body.
#[allow(clippy::too_many_arguments)]
fn exchange(
    sender: &IdentifierPrefix,
    recipient: &IdentifierPrefix,
    transaction: &str,
    prior: &str,
    timestamp: DateTime<FixedOffset>,
    route: &str,
    query: FieldMap,
    attributes: FieldMap,
) -> ExchangeMessage {
    let body = ExchangeBody {
        sender: sender.clone(),
        recipient: recipient.clone(),
        exchange: transaction.to_string(),
        prior: prior.to_string(),
        content: Timestamped {
            sender: None,
            timestamp,
            data: Exchange::Other {
                route: route.to_string(),
                query,
                attributes,
            },
        },
    };
    KeriEvent::new(
        KeriVersion::V2_0,
        SerializationFormats::JSON,
        HashFunctionCode::Blake3_256.into(),
        body,
    )
}

/// The `q` and `a` blocks of an exchange read with a route.
fn blocks<'a>(
    exn: &'a ExchangeMessage,
    route: &str,
) -> Result<(&'a FieldMap, &'a FieldMap), IpexError> {
    match &exn.data.content.data {
        Exchange::Other {
            route: read,
            query,
            attributes,
        } if read == route => Ok((query, attributes)),
        other => Err(IpexError::Format(format!(
            "expected {route}, read {}",
            other.route()
        ))),
    }
}

fn message_text(attributes: &FieldMap) -> Option<&str> {
    match attributes.get("m") {
        Some(FieldValue::String(text)) => Some(text),
        _ => None,
    }
}

/// Verifies that the exchange's sender signed it, and every signature.
fn verify_signatures<D: EventDatabase>(
    exn: &ExchangeMessage,
    signatures: &[Signature],
    kel: &EventStorage<D>,
) -> Result<(), IpexError> {
    let sender = &exn.data.sender;
    if kel.get_state(sender).is_none() {
        return Err(IpexError::UnknownSender(sender.clone()));
    }
    if !signatures
        .iter()
        .any(|signature| signature.get_signer().as_ref() == Some(sender))
    {
        return Err(IpexError::Signature(format!("{sender} did not sign it")));
    }
    let data = exn.encode().map_err(format)?;
    let validator = EventValidator::new(kel.events_db.clone());
    for signature in signatures {
        validator
            .verify(&data, signature)
            .map_err(|e| IpexError::Signature(e.to_string()))?;
    }
    Ok(())
}

/// The exchange and its signatures from a parsed message.
fn signed_exchange(message: &CesrMessage) -> Result<(ExchangeMessage, Vec<Signature>), IpexError> {
    let EventType::Exn(exn) = EventType::try_from(message.payload.clone()).map_err(format)? else {
        return Err(IpexError::Format("not an exchange".into()));
    };
    let mut signatures = vec![];
    for group in &message.attachments {
        signatures.extend(get_signatures(group.clone()).map_err(format)?);
    }
    Ok((exn, signatures))
}

fn to_cesr(message: CesrMessage) -> Result<Vec<u8>, IpexError> {
    message
        .to_cesr()
        .map_err(|_| IpexError::Format("cannot write the message".into()))
}

fn payload(exn: &ExchangeMessage) -> Result<Payload, IpexError> {
    Ok(Payload::JSON(exn.encode().map_err(format)?))
}

/// A Discloser's grant of one ACDC.
#[derive(Debug, Clone, PartialEq)]
pub struct Grant {
    pub exchange: ExchangeMessage,
    pub signatures: Vec<Signature>,
    pub acdc: Acdc,
    /// The blinded state block of the ACDC's registry head, disclosed with
    /// it.
    pub block: Option<StateBlock>,
}

impl Grant {
    /// An unsigned grant of `acdc` from `sender` to `recipient`, opening a
    /// new transaction, with the disclosure plan keripy derives for one ACDC
    /// disclosed whole.
    pub fn new(
        sender: &IdentifierPrefix,
        recipient: &IdentifierPrefix,
        message: &str,
        acdc: Acdc,
        block: Option<StateBlock>,
    ) -> Self {
        Self::at(
            sender,
            recipient,
            message,
            acdc,
            block,
            &transaction(),
            Utc::now().into(),
        )
    }

    /// As [`Grant::new`], in the transaction `transaction`, at `timestamp`.
    pub fn at(
        sender: &IdentifierPrefix,
        recipient: &IdentifierPrefix,
        message: &str,
        acdc: Acdc,
        block: Option<StateBlock>,
        transaction: &str,
        timestamp: DateTime<FixedOffset>,
    ) -> Self {
        let plan = FieldValue::List(vec![FieldValue::List(vec![FieldValue::List(vec![
            text(acdc.schema_said()),
            text("/"),
            FieldValue::List(vec![]),
        ])])]);
        let query = FieldMap(vec![("dp".into(), plan)]);
        let attributes = FieldMap(vec![
            ("m".into(), text(message)),
            ("o".into(), FieldValue::List(vec![text(acdc.said())])),
        ]);
        Grant {
            exchange: exchange(
                sender,
                recipient,
                transaction,
                "",
                timestamp,
                GRANT,
                query,
                attributes,
            ),
            signatures: vec![],
            acdc,
            block,
        }
    }

    /// The bytes the sender signs: the exchange body.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, IpexError> {
        self.exchange.encode().map_err(format)
    }

    pub fn signed(self, signatures: Vec<Signature>) -> Self {
        Grant { signatures, ..self }
    }

    pub fn message(&self) -> Option<&str> {
        blocks(&self.exchange, GRANT)
            .ok()
            .and_then(|(_, attributes)| message_text(attributes))
    }

    /// The grant with its signatures and the nested ACDC.
    pub fn to_cesr(&self) -> Result<Vec<u8>, IpexError> {
        let block = self
            .block
            .as_ref()
            .map(|block| {
                let group = block.to_group()?;
                match cesrox::group::parse_group(group.as_bytes()) {
                    Ok((group, [])) => Ok(group),
                    _ => Err(RegistryError::Format("not one state block group".into())),
                }
            })
            .transpose()?;
        let acdc = CesrMessage {
            payload: Payload::JSON(self.acdc.raw().to_vec()),
            attachments: block.into_iter().collect(),
            nested: vec![],
        };
        to_cesr(CesrMessage {
            payload: payload(&self.exchange)?,
            attachments: signatures_into_groups(&self.signatures),
            nested: vec![acdc],
        })
    }

    /// Reads one grant: the exchange, its signatures, and the one ACDC it
    /// discloses, which must be the one its `a.o` names.
    pub fn parse(bytes: &[u8]) -> Result<Self, IpexError> {
        match parse_cesr_stream_many(bytes).map_err(format)?.as_slice() {
            [message] => Self::from_message(message),
            _ => Err(IpexError::Format("not one grant".into())),
        }
    }

    fn from_message(message: &CesrMessage) -> Result<Self, IpexError> {
        let (exchange, signatures) = signed_exchange(message)?;
        let (_, attributes) = blocks(&exchange, GRANT)?;
        let [node] = message.nested.as_slice() else {
            return Err(IpexError::Format("a grant discloses one ACDC here".into()));
        };
        let acdc = Acdc::parse(&node.payload.to_vec()).map_err(format)?;
        match attributes.get("o") {
            Some(FieldValue::List(origins)) if origins.as_slice() == [text(acdc.said())] => {}
            _ => {
                return Err(IpexError::Format(
                    "a.o does not name the disclosed ACDC".into(),
                ))
            }
        }
        let mut blocks = vec![];
        for group in &node.attachments {
            blocks.extend(StateBlock::parse_group(&group.to_cesr_str())?);
        }
        if blocks.len() > 1 {
            return Err(IpexError::Format("more than one state block".into()));
        }
        Ok(Grant {
            exchange,
            signatures,
            acdc,
            block: blocks.pop(),
        })
    }

    /// Verifies the sender's signatures against its key state as known here.
    pub fn verify<D: EventDatabase>(&self, kel: &EventStorage<D>) -> Result<(), IpexError> {
        verify_signatures(&self.exchange, &self.signatures, kel)
    }
}

/// A fresh transaction identifier: the digest of a random nonce, as keripy
/// opens one.
fn transaction() -> String {
    HashFunction::from(HashFunctionCode::Blake3_256)
        .derive(Salt::random().to_qb64().as_bytes())
        .to_string()
}

/// A Disclosee's admit of a grant.
#[derive(Debug, Clone, PartialEq)]
pub struct Admit {
    pub exchange: ExchangeMessage,
    pub signatures: Vec<Signature>,
}

impl Admit {
    /// An unsigned admit of `grant` by its recipient, in its transaction.
    pub fn new(grant: &Grant, message: &str) -> Result<Self, IpexError> {
        Self::at(grant, message, Utc::now().into())
    }

    pub fn at(
        grant: &Grant,
        message: &str,
        timestamp: DateTime<FixedOffset>,
    ) -> Result<Self, IpexError> {
        let body = &grant.exchange.data;
        Ok(Admit {
            exchange: exchange(
                &body.recipient,
                &body.sender,
                &body.exchange,
                &grant.exchange.digest().map_err(format)?.to_string(),
                timestamp,
                ADMIT,
                FieldMap::default(),
                FieldMap(vec![("m".into(), text(message))]),
            ),
            signatures: vec![],
        })
    }

    pub fn signing_bytes(&self) -> Result<Vec<u8>, IpexError> {
        self.exchange.encode().map_err(format)
    }

    pub fn signed(self, signatures: Vec<Signature>) -> Self {
        Admit { signatures, ..self }
    }

    pub fn message(&self) -> Option<&str> {
        blocks(&self.exchange, ADMIT)
            .ok()
            .and_then(|(_, attributes)| message_text(attributes))
    }

    /// The SAID of the grant this admits.
    pub fn grant(&self) -> Result<SelfAddressingIdentifier, IpexError> {
        self.exchange.data.prior.parse().map_err(format)
    }

    pub fn to_cesr(&self) -> Result<Vec<u8>, IpexError> {
        to_cesr(CesrMessage {
            payload: payload(&self.exchange)?,
            attachments: signatures_into_groups(&self.signatures),
            nested: vec![],
        })
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, IpexError> {
        let messages = parse_cesr_stream_many(bytes).map_err(format)?;
        let [message] = messages.as_slice() else {
            return Err(IpexError::Format("not one admit".into()));
        };
        let (exchange, signatures) = signed_exchange(message)?;
        blocks(&exchange, ADMIT)?;
        if !message.nested.is_empty() {
            return Err(IpexError::Format(
                "an admit carries no nested message".into(),
            ));
        }
        Ok(Admit {
            exchange,
            signatures,
        })
    }

    /// Verifies the sender's signatures against its key state as known here.
    pub fn verify<D: EventDatabase>(&self, kel: &EventStorage<D>) -> Result<(), IpexError> {
        verify_signatures(&self.exchange, &self.signatures, kel)
    }
}

/// The registry events of `disclosure`, then `grant`, as one stream.
pub fn grant_stream(disclosure: &Disclosure, grant: &Grant) -> Result<Vec<u8>, IpexError> {
    let mut out = vec![];
    for event in std::iter::once(&disclosure.inception).chain(&disclosure.updates) {
        out.extend(event.encode());
    }
    out.extend(grant.to_cesr()?);
    Ok(out)
}

/// Reads a stream of registry events followed by a grant, as
/// [`grant_stream`] writes it: the grant and the presentation it makes with
/// those events.
pub fn parse_grant_stream(bytes: &[u8]) -> Result<(Presentation, Grant), IpexError> {
    let mut messages = parse_cesr_stream_many(bytes).map_err(format)?;
    let grant = Grant::from_message(
        &messages
            .pop()
            .ok_or_else(|| IpexError::Format("no grant".into()))?,
    )?;
    let mut events = messages
        .iter()
        .map(|message| {
            if !message.attachments.is_empty() || !message.nested.is_empty() {
                return Err(IpexError::Format(
                    "a registry event carries no attachments".into(),
                ));
            }
            Ok(RegistryMessage::parse(&message.payload.to_vec())?)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter();
    let inception = events
        .next()
        .ok_or_else(|| IpexError::Format("no registry events before the grant".into()))?;
    let presentation = Presentation {
        acdc: grant.acdc.clone(),
        disclosure: Disclosure {
            inception,
            updates: events.collect(),
            block: grant.block.clone(),
        },
    };
    Ok((presentation, grant))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use keri_core::{
        actor::parse_event_stream,
        database::redb::RedbDatabase,
        event_message::signed_event_message::{Message, Notice},
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    };
    use serde_json::Value;
    use tempfile::NamedTempFile;

    use super::{grant_stream, parse_grant_stream, Admit, Grant, IpexError};
    use crate::registry::{Binding, MemoryRegistryStore, Policy, Validator, Verdict};

    /// An issuer's /ipex/grant of an ACDC in a private registry and the
    /// holder's /ipex/admit, as keripy 424a50c writes them
    /// (test-vectors/acdc/ipex/gen_keripy.py).
    fn keripy() -> Value {
        serde_json::from_str(include_str!("../../../test-vectors/acdc/ipex/keripy.json")).unwrap()
    }

    fn text<'a>(vectors: &'a Value, key: &str) -> &'a str {
        vectors[key].as_str().unwrap()
    }

    /// A KEL store holding the issuer's and the holder's KELs.
    fn kels(vectors: &Value) -> (NamedTempFile, EventStorage<RedbDatabase>) {
        let path = NamedTempFile::new().unwrap();
        let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
        let processor = BasicProcessor::new(db.clone(), None);
        for kel in ["issuer_kel", "holder_kel"] {
            for message in parse_event_stream(text(vectors, kel).as_bytes()).unwrap() {
                let Message::Notice(notice @ Notice::Event(_)) = message else {
                    panic!("not a key event")
                };
                processor.process_notice(&notice).unwrap();
            }
        }
        (path, EventStorage::new(db))
    }

    /// The exchange body at the start of a signed stream.
    fn body(stream: &str) -> &str {
        &stream[..stream.find("}-").unwrap() + 1]
    }

    /// keriox reads keripy's grant and admit, verifies their signatures, and
    /// writes the same exchange bodies from the same fields.
    #[test]
    fn grant_and_admit_are_keripys() {
        let vectors = keripy();
        let (_path, kel) = kels(&vectors);

        let grant = Grant::parse(text(&vectors, "grant").as_bytes()).unwrap();
        grant.verify(&kel).unwrap();
        assert_eq!(grant.message(), Some("Your diploma"));
        assert_eq!(grant.acdc.raw(), text(&vectors, "acdc").as_bytes());
        let block = grant.block.clone().unwrap();
        assert_eq!(block.to_group().unwrap()[4..], *text(&vectors, "block"));
        assert_eq!(
            String::from_utf8(grant.signing_bytes().unwrap()).unwrap(),
            body(text(&vectors, "grant"))
        );
        assert_eq!(Grant::parse(&grant.to_cesr().unwrap()).unwrap(), grant);

        let built = Grant::at(
            &text(&vectors, "issuer").parse().unwrap(),
            &text(&vectors, "holder").parse().unwrap(),
            "Your diploma",
            grant.acdc.clone(),
            Some(block),
            &grant.exchange.data.exchange,
            grant.exchange.data.content.timestamp,
        );
        assert_eq!(
            built.signing_bytes().unwrap(),
            grant.signing_bytes().unwrap()
        );

        let admit = Admit::parse(text(&vectors, "admit").as_bytes()).unwrap();
        admit.verify(&kel).unwrap();
        assert_eq!(admit.message(), Some("Thanks"));
        assert_eq!(admit.grant().unwrap(), grant.exchange.digest().unwrap());
        let built = Admit::at(&grant, "Thanks", admit.exchange.data.content.timestamp).unwrap();
        assert_eq!(
            built.signing_bytes().unwrap(),
            admit.signing_bytes().unwrap()
        );
        assert_eq!(Admit::parse(&admit.to_cesr().unwrap()).unwrap(), admit);
    }

    /// keripy's registry events and grant, sent as one stream, make a
    /// presentation that verifies against the issuer's KEL.
    #[test]
    fn a_keripy_grant_presents_its_credential() {
        let vectors = keripy();
        let (_path, kel) = kels(&vectors);
        let grant = Grant::parse(text(&vectors, "grant").as_bytes()).unwrap();
        let mut stream = text(&vectors, "rip").as_bytes().to_vec();
        stream.extend(text(&vectors, "bup").as_bytes());
        stream.extend(grant.to_cesr().unwrap());

        let (presentation, received) = parse_grant_stream(&stream).unwrap();
        assert_eq!(received, grant);
        assert_eq!(
            grant_stream(&presentation.disclosure, &received).unwrap(),
            stream
        );
        let validator = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let binding = presentation.binding().unwrap();
        let verdict = validator
            .accept(&kel, &presentation.disclosure, Some(&binding))
            .unwrap();
        let Verdict::Valid { state, .. } = verdict else {
            panic!("{verdict:?}")
        };
        assert_eq!(state.state.as_deref(), Some("issued"));
        assert_eq!(state.binding, Some(Binding::Mutual));
    }

    /// A grant whose body was changed after signing, or that names another
    /// ACDC than it carries, is refused.
    #[test]
    fn an_altered_grant_is_refused() {
        let vectors = keripy();
        let (_path, kel) = kels(&vectors);
        let original = text(&vectors, "grant");

        let renamed = original.replace("Your diploma", "Your diplomb");
        let grant = Grant::parse(renamed.as_bytes()).unwrap();
        assert!(matches!(grant.verify(&kel), Err(IpexError::Signature(_))));

        let mut grant = Grant::parse(original.as_bytes()).unwrap();
        grant.signatures.clear();
        assert!(matches!(grant.verify(&kel), Err(IpexError::Signature(_))));

        // a.o names the ACDC's registry instead of the ACDC.
        let other_said = text(&vectors, "registry").to_string();
        let mut other = grant.exchange.clone();
        if let keri_core::exchange::Exchange::Other { attributes, .. } =
            &mut other.data.content.data
        {
            attributes.0[1].1 = keri_core::event_message::field_map::FieldValue::List(vec![
                keri_core::event_message::field_map::FieldValue::String(other_said),
            ]);
        }
        let misnamed = Grant {
            exchange: other,
            ..grant
        };
        assert!(Grant::parse(&misnamed.to_cesr().unwrap()).is_err());
    }

    /// Writes a grant made by keriox, of a credential to keripy's holder,
    /// for test-vectors/acdc/ipex/check_keriox.py to verify with keripy's
    /// own IPEX handler. Runs only when IPEX_KERIOX_OUT names the file.
    #[test]
    fn writes_a_keriox_grant_for_keripy() {
        use acdc::{Acdc, Block, HashFunctionCode, Kind};

        use crate::registry::{verify::tests::Issuer, Blinding, RegistryIssuer};

        let Ok(out) = std::env::var("IPEX_KERIOX_OUT") else {
            return;
        };
        let vectors = keripy();
        let holder = text(&vectors, "holder");
        // keripy's default schema for field map ACDCs, embedded whole so
        // that keripy need not resolve it.
        let keripy_acdc = Acdc::parse(text(&vectors, "acdc").as_bytes()).unwrap();
        let acdc::value::Value::Object(schema) = keripy_acdc.to_field_map()["s"].clone() else {
            panic!("keripy's ACDC embeds its schema")
        };

        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let blinding = Blinding::private();
        let rip = registrar.incept(&issuer.id).unwrap();
        let acdc = Acdc::builder(issuer.id.to_string(), "")
            .schema_block(schema)
            .registry(rip.event.said().unwrap().to_string())
            .attributes(Block::new().with_issuee(holder).with("degree", "MSc"))
            .build(Kind::Json, HashFunctionCode::Blake3_256)
            .unwrap();
        let issued = registrar
            .issue_after(&rip, &blinding, &acdc.said().parse().unwrap())
            .unwrap();
        issuer.anchor(vec![rip.seal().unwrap(), issued.seal().unwrap()]);
        registrar.commit(&rip).unwrap();
        registrar.commit(&issued).unwrap();

        let grant = Grant::new(
            &issuer.id,
            &holder.parse().unwrap(),
            "Your diploma, from keriox",
            acdc,
            issued.block.clone(),
        );
        let signature = issuer.sign(&grant.signing_bytes().unwrap());
        let grant = grant.signed(vec![signature]);
        let disclosure = registrar.disclosure(&rip.event.said().unwrap()).unwrap();
        let written = serde_json::json!({
            "issuer_kel": String::from_utf8(issuer.kel()).unwrap(),
            "registry": rip.event.said().unwrap().to_string(),
            "rip": String::from_utf8(disclosure.inception.encode()).unwrap(),
            "bup": String::from_utf8(disclosure.updates[0].encode()).unwrap(),
            "grant": String::from_utf8(grant.to_cesr().unwrap()).unwrap(),
            "grant_said": grant.exchange.digest().unwrap().to_string(),
        });
        std::fs::write(out, serde_json::to_string_pretty(&written).unwrap()).unwrap();
    }
}
