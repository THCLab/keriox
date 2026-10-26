use crate::event_message::keri_version::KeriVersion;
use cesrox::cesr_proof::MaterialPath;
use said::derivation::HashFunctionCode;
use said::version::format::SerializationFormats;
use serde::{Deserialize, Serialize};

use crate::event::KeyEvent;
use crate::event_message::msg::KeriEvent;
use crate::event_message::timestamped::Timestamped;
use crate::prefix::IdentifierPrefix;

use crate::event_message::{signature::Signature, EventTypeTag, Typeable};

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
    // signature of event anchored in exn message in `a` field
    pub data_signature: (MaterialPath, Vec<Signature>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum Exchange {
    #[serde(rename = "/fwd")]
    Fwd {
        #[serde(rename = "q")]
        args: FwdArgs,
        #[serde(rename = "a")]
        to_forward: KeriEvent<KeyEvent>,
    },
}

impl Exchange {
    /// The exchange as a message sent by `sender` to the recipient it
    /// names. Exchange messages are KERI 2.0 messages; this one is not part
    /// of a transaction.
    pub fn to_message(
        self,
        sender: &IdentifierPrefix,
        format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> ExchangeMessage {
        let body = ExchangeBody {
            sender: sender.clone(),
            recipient: self.get_prefix(),
            exchange: String::new(),
            prior: String::new(),
            content: Timestamped::new(self),
        };
        KeriEvent::new(KeriVersion::V2_0, format, derivation.into(), body)
    }
}

impl Exchange {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Exchange::Fwd {
                args,
                to_forward: _,
            } => args.recipient_id.clone(),
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
        Exchange::Fwd {
            args: FwdArgs {
                recipient_id: "EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1"
                    .parse()
                    .unwrap(),
                topic: ForwardTopic::Multisig,
            },
            to_forward: serde_json::from_str(ICP).unwrap(),
        }
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
}
