//! Routed messages of the KERI specification that keriox reads but does
//! not serve: the exchange transaction inception `xip`, the prod `pro` and
//! the bare message `bar`. Their blocks are kept as read, so they are
//! written back byte for byte.

use serde::{Deserialize, Serialize};

use super::{
    field_map::FieldMap, msg::KeriEvent, timestamped::Timestamped, EventTypeTag, Typeable,
};
use crate::prefix::IdentifierPrefix;

/// `xip` after `d`: `[u, i, ri, dt, r, q, a]`, all required.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct XipBody {
    /// The salty nonce that makes the transaction's SAID unique.
    #[serde(rename = "u")]
    pub salt: String,
    #[serde(rename = "i")]
    pub sender: IdentifierPrefix,
    #[serde(rename = "ri")]
    pub recipient: IdentifierPrefix,
    #[serde(flatten)]
    pub content: Timestamped<XipBlocks>,
}

/// The route and blocks of an `xip`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct XipBlocks {
    #[serde(rename = "r")]
    pub route: String,
    #[serde(rename = "q")]
    pub query: FieldMap,
    #[serde(rename = "a")]
    pub attributes: FieldMap,
}

impl Typeable for XipBody {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Xip
    }
}

/// A `pro`: shaped like a query, asking for sealed data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Prod {
    #[serde(rename = "r")]
    pub route: String,
    #[serde(rename = "rr")]
    pub reply_route: String,
    #[serde(rename = "q")]
    pub query: FieldMap,
}

impl Typeable for Prod {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Pro
    }
}

/// A `bar`: shaped like a reply, returning sealed data.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Bare {
    #[serde(rename = "r")]
    pub route: String,
    #[serde(rename = "a")]
    pub attributes: FieldMap,
}

impl Typeable for Bare {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Bar
    }
}

pub type XipMessage = KeriEvent<XipBody>;
pub type ProdMessage = KeriEvent<Timestamped<Prod>>;
pub type BareMessage = KeriEvent<Timestamped<Bare>>;

#[cfg(test)]
mod tests {
    use crate::event_message::cesr_adapter::{parse_event_type, EventType};

    const XIP: &str = r#"{"v":"KERICAACAAJSONAAFn.","t":"xip","d":"EJbE2agA3239Iusld1lNvFAxRuhv1SX0mAxxUm67gWOU","u":"0ABrZXJpc3BlY3dvcmtyYXcw","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","ri":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08-30T13:30:10.123456+00:00","r":"/offer","q":{"timing":"immediate"},"a":{"action":"sell","item":"Rembrant","price":300000.0}}"#;
    const PRO: &str = r#"{"v":"KERICAACAAJSONAAEp.","t":"pro","d":"EHNqhJXgUdYHFzNiuO7Ue06QWRnOMjhTrVt_QGOfZjH_","i":"EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur","dt":"2025-08-21T17:50:00.000000+00:00","r":"/confidential","rr":"/confidential/process","q":{"i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","name":true}}"#;
    const BAR: &str = r#"{"v":"KERICAACAAJSONAAEV.","t":"bar","d":"EMSlSHIe04CuAqhz55nAnBpE_0T65Sqs2fmaPpsNIbnn","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08-22T17:52:00.000000+00:00","r":"/confidential/process","a":{"i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","name":"Ean"}}"#;

    /// The specification's examples read as their types, with SAIDs that
    /// verify, and are written back unchanged.
    #[test]
    fn the_examples_of_the_specification_round_trip() {
        match parse_event_type(XIP.as_bytes()).unwrap() {
            EventType::Xip(xip) => {
                xip.check_digest().unwrap();
                assert_eq!(xip.data.salt, "0ABrZXJpc3BlY3dvcmtyYXcw");
                assert_eq!(xip.data.content.data.route, "/offer");
            }
            other => panic!("xip read as {other:?}"),
        }
        match parse_event_type(PRO.as_bytes()).unwrap() {
            EventType::Pro(pro) => {
                pro.check_digest().unwrap();
                assert_eq!(pro.data.data.reply_route, "/confidential/process");
            }
            other => panic!("pro read as {other:?}"),
        }
        match parse_event_type(BAR.as_bytes()).unwrap() {
            EventType::Bar(bar) => {
                bar.check_digest().unwrap();
                assert!(bar.data.data.attributes.get("name").is_some());
            }
            other => panic!("bar read as {other:?}"),
        }
    }

    /// These messages exist in KERI 2.0 only.
    #[test]
    fn a_keri_1_prod_is_refused() {
        let pro = parse_event_type(PRO.as_bytes()).unwrap();
        let EventType::Pro(pro) = pro else { panic!() };
        let keri1 = super::ProdMessage::new(
            crate::event_message::keri_version::KeriVersion::V1_0,
            said::version::format::SerializationFormats::JSON,
            said::derivation::HashFunctionCode::Blake3_256.into(),
            pro.data,
        );
        let refused = parse_event_type(&keri1.encode().unwrap()).unwrap_err();
        assert!(refused.to_string().contains("KERI 2.0"), "{refused}");
    }
}
