use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{EventTypeTag, SaidEvent, Typeable},
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
};

use super::Timestamped;

// TODO: make enum with different query args
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryData {
    #[serde(flatten)]
    pub route: QueryRoute,

    #[serde(rename = "rr")]
    pub reply_route: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum QueryRoute {
    #[serde(rename = "log")]
    Log {
        #[serde(rename = "q")]
        args: QueryArgs,
    },
    #[serde(rename = "ksn")]
    Ksn {
        #[serde(rename = "q")]
        args: QueryArgs,
    },
    #[serde(rename = "mbx")]
    Mbx {
        #[serde(rename = "q")]
        args: QueryArgsMbx,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgsMbx {
    /// Controller's currently used indentifier
    pub i: IdentifierPrefix,
    /// Identifier to be queried
    pub pre: IdentifierPrefix,
    /// To which witness given query message reply will be sent
    pub src: IdentifierPrefix,

    pub topics: QueryTopics,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTopics {
    #[serde(rename = "/receipt")]
    pub receipt: u64,
    #[serde(rename = "/replay")]
    pub replay: u64,
    #[serde(rename = "/multisig")]
    pub multisig: u64,
    #[serde(rename = "/credential")]
    pub credential: u64,
    #[serde(rename = "/delegate")]
    pub delegate: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,
    pub i: IdentifierPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<IdentifierPrefix>,
}

pub type QueryEvent = EventMessage<SaidEvent<Timestamped<QueryData>>>;

impl QueryEvent {
    pub fn new_query(
        route: QueryRoute,
        serialization_format: SerializationFormats,
        derivation: &SelfAddressing,
    ) -> Result<Self, Error> {
        let message = QueryData {
            reply_route: "route".into(),
            route,
        };

        let env = Timestamped::new(message);
        env.to_message(serialization_format, derivation)
    }

    pub fn get_query_data(&self) -> QueryData {
        self.event.content.data.clone()
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self.event.content.data.route {
            QueryRoute::Log { ref args } | QueryRoute::Ksn { ref args } => args.i.clone(),
            QueryRoute::Mbx { ref args } => args.i.clone(),
        }
    }
}

impl Typeable for QueryData {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Qry
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedQuery {
    pub query: QueryEvent,
    pub signer: IdentifierPrefix,
    pub signatures: Vec<AttachedSignaturePrefix>,
}

impl SignedQuery {
    pub fn new(
        envelope: QueryEvent,
        signer: IdentifierPrefix,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        Self {
            query: envelope,
            signer,
            signatures,
        }
    }
}

#[test]
fn test_query_deserialize() {
    // taken from keripy keripy/tests/core/test_eventing.py::test_messegize (line 1462)
    let input_query = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.event.content.data,
        QueryData {
            route: QueryRoute::Log { .. },
            ..
        }
    ));
}

#[test]
fn test_query_mbx_deserialize() {
    let input_query = r#"{"v":"KERI10JSON000183_","t":"qry","d":"E8iit8ptMCToTUuHOxChftPNjFYYTMmwQzKQTmad6pA4","dt":"2022-03-21T11:13:25.001836+00:00","r":"mbx","rr":"","q":{"pre":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","topics":{"/receipt":0,"/replay":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.event.content.data,
        QueryData {
            route: QueryRoute::Mbx {
                args: QueryArgsMbx {
                    topics: QueryTopics {
                        receipt: 0,
                        replay: 0,
                        multisig: 0,
                        credential: 0,
                        delegate: 0
                    },
                    ..
                }
            },
            ..
        }
    ));
}
