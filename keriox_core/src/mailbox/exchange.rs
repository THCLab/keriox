use crate::event_message::keri_version::KeriVersion;
use said::derivation::{HashFunction, HashFunctionCode};
use said::SelfAddressingIdentifier;
use said::version::format::SerializationFormats;
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use crate::event_message::field_map::FieldMap;

use crate::event_message::msg::KeriEvent;
use crate::event_message::timestamped::Timestamped;
use crate::prefix::IdentifierPrefix;

use crate::event_message::{
    signature::Signature, signed_event_message::Message, EventTypeTag, Typeable,
};

pub type ExchangeMessage = KeriEvent<ExchangeBody>;

/// The body of an `exn` after `d`, in the field order of the KERI
/// specification: `[v, t, d, i, ri, x, p, dt, r, q, a]`. Every field is
/// required.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ExchangeBody {
    #[serde(rename = "i")]
    pub sender: IdentifierPrefix,
    #[serde(rename = "ri")]
    pub recipient: IdentifierPrefix,
    /// The SAID of the `xip` that opened the transaction this message
    /// belongs to; empty when it is not part of a transaction.
    #[serde(rename = "x")]
    pub exchange: String,
    /// The SAID of the previous message of the transaction; empty when the
    /// message is not part of a transaction.
    #[serde(rename = "p")]
    pub prior: String,
    #[serde(flatten)]
    pub content: Timestamped<Exchange>,
}

impl Typeable for ExchangeBody {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Exn
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignedExchange {
    pub exchange_message: ExchangeMessage,
    pub signature: Vec<Signature>,
    /// The messages carried nested in the exchange's attachments, each with
    /// its own: for a forward, the one message it forwards.
    pub nested: Vec<Message>,
}

impl SignedExchange {
    /// A forward and the message it forwards.
    pub fn forward(
        exchange_message: ExchangeMessage,
        signature: Vec<Signature>,
        forwarded: Message,
    ) -> Self {
        Self {
            exchange_message,
            signature,
            nested: vec![forwarded],
        }
    }
}

/// The route, `r`, of an exchange and its `q` and `a` blocks.
#[derive(Debug, Clone, PartialEq)]
pub enum Exchange {
    /// `/fwd`: a message for the mailbox of `q.pre`. The message is nested
    /// in the exchange's attachments, its own attachments with it; `a.evt`
    /// is the digest of its body, as keripy forwards in KERI 2.0.
    Fwd {
        args: FwdArgs,
        forwarded: SelfAddressingIdentifier,
    },
    /// Any other route. keriox reads it, keeping its blocks as they are,
    /// but serves none.
    Other {
        route: String,
        query: FieldMap,
        attributes: FieldMap,
    },
}

const FWD: &str = "/fwd";

/// The `a` block of a forward.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ForwardedBody {
    evt: SelfAddressingIdentifier,
}

impl Exchange {
    /// A forward of the message whose body is `body` to the mailbox of
    /// `recipient` under `topic`.
    pub fn forward(recipient: &IdentifierPrefix, topic: ForwardTopic, body: &[u8]) -> Self {
        Exchange::Fwd {
            args: FwdArgs {
                recipient_id: recipient.clone(),
                topic,
            },
            forwarded: HashFunction::from(HashFunctionCode::Blake3_256).derive(body),
        }
    }

    /// Whether `body` is the body of the message a forward names.
    pub fn forwards(&self, body: &[u8]) -> bool {
        match self {
            Exchange::Fwd { forwarded, .. } => forwarded.verify_binding(body),
            Exchange::Other { .. } => false,
        }
    }
}

impl Serialize for Exchange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut body = serializer.serialize_struct("Exchange", 3)?;
        match self {
            Exchange::Fwd { args, forwarded } => {
                body.serialize_field("r", FWD)?;
                body.serialize_field("q", args)?;
                body.serialize_field(
                    "a",
                    &ForwardedBody {
                        evt: forwarded.clone(),
                    },
                )?;
            }
            Exchange::Other {
                route,
                query,
                attributes,
            } => {
                body.serialize_field("r", route)?;
                body.serialize_field("q", query)?;
                body.serialize_field("a", attributes)?;
            }
        }
        body.end()
    }
}

impl<'de> Deserialize<'de> for Exchange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Blocks {
            r: String,
            q: FieldMap,
            a: FieldMap,
        }
        let Blocks { r, q, a } = Blocks::deserialize(deserializer)?;
        if r == FWD {
            // The blocks of a forward have a fixed shape, read as such
            // from their JSON form, whatever kind the body is in.
            let json = |block: FieldMap| serde_json::to_string(&block).map_err(de::Error::custom);
            let ForwardedBody { evt } =
                serde_json::from_str(&json(a)?).map_err(de::Error::custom)?;
            Ok(Exchange::Fwd {
                args: serde_json::from_str(&json(q)?).map_err(de::Error::custom)?,
                forwarded: evt,
            })
        } else {
            Ok(Exchange::Other {
                route: r,
                query: q,
                attributes: a,
            })
        }
    }
}

impl Exchange {
    /// The exchange as a message from `sender` to `recipient`. Exchange
    /// messages are KERI 2.0 messages; this one is not part of a
    /// transaction.
    pub fn to_message(
        self,
        sender: &IdentifierPrefix,
        recipient: &IdentifierPrefix,
        format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> ExchangeMessage {
        let body = ExchangeBody {
            sender: sender.clone(),
            recipient: recipient.clone(),
            exchange: String::new(),
            prior: String::new(),
            content: Timestamped::new(self),
        };
        KeriEvent::new(KeriVersion::V2_0, format, derivation.into(), body)
    }

    /// The route, `r`.
    pub fn route(&self) -> &str {
        match self {
            Exchange::Fwd { .. } => FWD,
            Exchange::Other { route, .. } => route,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FwdArgs {
    #[serde(rename = "pre")]
    pub recipient_id: IdentifierPrefix,
    pub topic: ForwardTopic,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardTopic {
    Multisig,
    Delegate,
}

impl Typeable for Exchange {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Exn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ICP: &str = r#"{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}"#;

    fn forward() -> Exchange {
        Exchange::forward(
            &"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"
                .parse()
                .unwrap(),
            ForwardTopic::Multisig,
            ICP.as_bytes(),
        )
    }

    /// A forward names the message it forwards by the digest of its body,
    /// in `a.evt`, and nothing else.
    #[test]
    fn a_forward_names_the_digest_of_the_forwarded_body() {
        let fwd = forward();
        assert!(fwd.forwards(ICP.as_bytes()));
        assert!(!fwd.forwards(ICP.replace("\"s\":\"0\"", "\"s\":\"1\"").as_bytes()));
        let a = serde_json::to_value(&fwd).unwrap()["a"].clone();
        assert_eq!(a.as_object().unwrap().keys().collect::<Vec<_>>(), ["evt"]);

        let mut with_more = serde_json::to_value(&fwd).unwrap();
        with_more["a"]["extra"] = serde_json::json!("x");
        with_more["dt"] = serde_json::json!("2020-08-30T13:42:11.123456+00:00");
        assert!(serde_json::from_value::<Timestamped<Exchange>>(with_more).is_err());
    }

    /// An exchange is written with the fields of the specification, in its
    /// order, as a KERI 2.0 message outside any transaction.
    #[test]
    fn an_exchange_has_the_fields_of_the_specification() {
        let sender: IdentifierPrefix = "EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4"
            .parse()
            .unwrap();
        let exn = forward().to_message(
            &sender,
            &"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1".parse().unwrap(),
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        );
        let body = String::from_utf8(exn.encode().unwrap()).unwrap();
        let fields: Vec<String> =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&body)
                .unwrap()
                .keys()
                .cloned()
                .collect();
        let mut in_order = fields.clone();
        in_order.sort_by_key(|f| body.find(&format!("\"{f}\":")).unwrap());
        assert_eq!(
            in_order,
            ["v", "t", "d", "i", "ri", "x", "p", "dt", "r", "q", "a"]
        );
        assert!(body.starts_with(r#"{"v":"KERICAACAAJSON"#), "{body}");
        assert_eq!(exn.data.sender, sender);
        assert_eq!(
            exn.data.recipient.to_string(),
            "EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"
        );
        assert_eq!(
            (exn.data.exchange.as_str(), exn.data.prior.as_str()),
            ("", "")
        );

        let parsed: ExchangeMessage = serde_json::from_str(&body).unwrap();
        assert_eq!(String::from_utf8(parsed.encode().unwrap()).unwrap(), body);
    }

    /// A body without the required fields is not an exchange.
    #[test]
    fn an_exchange_without_i_ri_x_p_is_refused() {
        let exn = forward().to_message(
            &"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4"
                .parse()
                .unwrap(),
            &"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"
                .parse()
                .unwrap(),
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        );
        let mut body: serde_json::Value = serde_json::from_slice(&exn.encode().unwrap()).unwrap();
        for field in ["i", "ri", "x", "p"] {
            let mut short = body.clone();
            short.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<ExchangeMessage>(short).is_err(),
                "an exn without {field} was read"
            );
        }
        body.as_object_mut().unwrap().remove("dt");
        assert!(serde_json::from_value::<ExchangeMessage>(body).is_err());
    }

    /// The specification's example exchange, on a route keriox does not
    /// serve, is read with its blocks as they are and written back
    /// unchanged.
    #[test]
    fn an_exchange_of_another_route_round_trips() {
        let raw = r#"{"v":"KERICAACAAJSONAAGt.","t":"exn","d":"EEIp1e5v4L6rt7cp1nRsn4mN6bJVUDyIQEATIzxR8UnE","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","ri":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","x":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU","p":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU","dt":"2020-08-30T13:42:11.123456+00:00","r":"/agree","q":{"timing":"immediate"},"a":{"action":"buy","item":"Rembrant","price":300000.0}}"#;
        let exn: ExchangeMessage = serde_json::from_str(raw).unwrap();
        exn.check_digest().unwrap();
        match &exn.data.content.data {
            Exchange::Other {
                route, attributes, ..
            } => {
                assert_eq!(route, "/agree");
                let labels: Vec<&str> = attributes.0.iter().map(|(l, _)| l.as_str()).collect();
                assert_eq!(labels, ["action", "item", "price"]);
            }
            other => panic!("read as {other:?}"),
        }
        assert_eq!(String::from_utf8(exn.encode().unwrap()).unwrap(), raw);
    }

    /// A forward whose blocks do not have a forward's shape is refused,
    /// not read as some other route.
    #[test]
    fn a_malformed_forward_is_refused() {
        let exn = forward().to_message(
            &"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4".parse().unwrap(),
            &"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1".parse().unwrap(),
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        );
        let mut body: serde_json::Value = serde_json::from_slice(&exn.encode().unwrap()).unwrap();
        body["q"] = serde_json::json!({"topic": "multisig"});
        assert!(serde_json::from_value::<ExchangeMessage>(body).is_err());
    }
}

