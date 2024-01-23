use keri_core::{
    event_message::{msg::KeriEvent, timestamped::Timestamped, EventTypeTag, Typeable},
    prefix::IdentifierPrefix,
    query::query_event::SignedQuery,
};
use serde::{Deserialize, Serialize};

pub type QueryEvent = KeriEvent<Timestamped<TelQueryRoute>>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum TelQueryRoute {
    #[serde(rename = "tels")]
    Tels {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: TelQueryArgs,
    },
}

impl Typeable for TelQueryRoute {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Qry
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TelQueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub i: Option<IdentifierPrefix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ri: Option<IdentifierPrefix>,
}

pub type SignedTelQuery = SignedQuery<TelQueryEvent>;
pub type TelQueryEvent = KeriEvent<Timestamped<TelQueryRoute>>;

#[test]
pub fn query() {
    let qry_raw = r#"{"v":"KERI10JSON0000fe_","t":"qry","d":"EHraBkp-XMf1x_bo70O2x3brBCHlJHa7q_MzsBNeYz2_","dt":"2021-01-01T00:00:00.000000+00:00","r":"tels","rr":"","q":{"i":"EA8Ih8hxLi3mmkyItXK1u55cnHl4WgNZ_RE-gKXqgcX4","ri":"EO0_SyqPS1-EVYSITakYpUHaUZZpZGsjaXFOaO_kCfS4"}}"#;
    let qry: QueryEvent = serde_json::from_reader(qry_raw.as_bytes()).unwrap();

    let serialized = qry.encode().unwrap();
    assert_eq!(qry_raw.as_bytes(), serialized);
}
