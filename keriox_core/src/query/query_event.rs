use serde::{Deserialize, Serialize};

use super::Timestamped;
use crate::{
    error::Error,
    event::{EventMessage, SerializationFormats},
    event_message::{
        signed_event_message::{SignedEventMessage, SignedNontransferableReceipt},
        EventTypeTag, SaidEvent, Typeable,
    },
    prefix::{AttachedSignaturePrefix, IdentifierPrefix},
    sai::derivation::SelfAddressing,
};

// TODO: make enum with different query args
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Query {
    #[serde(flatten)]
    pub route: QueryRoute,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum QueryRoute {
    #[serde(rename = "log")]
    Log {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: QueryArgs,
    },
    #[serde(rename = "ksn")]
    Ksn {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: QueryArgs,
    },
    #[serde(rename = "mbx")]
    Mbx {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: QueryArgsMbx,
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgsMbx {
    /// Controller's currently used indentifier
    pub pre: IdentifierPrefix,
    /// Types of mail to query and their minimum serial number
    pub topics: QueryTopics,
    /// Identifier to be queried
    pub i: IdentifierPrefix,
    /// To which witness given query message reply will be sent
    pub src: IdentifierPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTopics {
    #[serde(rename = "/receipt")]
    pub receipt: u64,
    #[serde(rename = "/replay")]
    pub replay: u64,
    #[serde(rename = "/reply")]
    pub reply: u64,
    #[serde(rename = "/multisig")]
    pub multisig: u64,
    #[serde(rename = "/credential")]
    pub credential: u64,
    #[serde(rename = "/delegate")]
    pub delegate: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct MailboxResponse {
    pub receipt: Vec<SignedNontransferableReceipt>,
    pub multisig: Vec<SignedEventMessage>,
    pub delegate: Vec<SignedEventMessage>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,
    pub i: IdentifierPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<IdentifierPrefix>,
}

pub type QueryEvent = EventMessage<SaidEvent<Timestamped<Query>>>;

impl QueryEvent {
    pub fn new_query(
        route: QueryRoute,
        serialization_format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<Self, Error> {
        let message = Query { route };

        let env = Timestamped::new(message);
        env.to_message(serialization_format, derivation)
    }

    pub fn get_query_data(&self) -> Query {
        self.event.content.data.clone()
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self.event.content.data.route {
            QueryRoute::Log { ref args, .. } | QueryRoute::Ksn { ref args, .. } => args.i.clone(),
            QueryRoute::Mbx { ref args, .. } => args.i.clone(),
        }
    }
}

impl Typeable for Query {
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
    // taken from keripy keripy/tests/core/test_eventing.py::test_messegize
    let input_query = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVwZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#; //-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.event.content.data,
        Query {
            route: QueryRoute::Log { .. },
            ..
        }
    ));

    assert_eq!(
        input_query,
        &String::from_utf8_lossy(&qr.serialize().unwrap())
    );
}

#[test]
fn test_query_mbx_deserialize() {
    let input_query = r#"{"v":"KERI10JSON000165_","t":"qry","d":"EKrOiJOMKnTLvJJz0j9hJ5acANkr_DFhVp6HgfjZLOUR","dt":"2022-10-25T09:53:04.454094+00:00","r":"mbx","rr":"","q":{"pre":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","src":"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"}}"#; //-VAj-HABEKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4-AABAAAQY9eL1n96itQTvVTEdKjb-xYFWy-SYylQopNeYpYEW9bJ96h4deDboGOUCzVUCQrZ2kt2UNFL3xSJn4ieWLAC"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.event.content.data,
        Query {
            route: QueryRoute::Mbx {
                args: QueryArgsMbx {
                    topics: QueryTopics {
                        receipt: 0,
                        replay: 0,
                        reply: 0,
                        multisig: 0,
                        credential: 0,
                        delegate: 0
                    },
                    ..
                },
                ..
            },
        }
    ));

    assert_eq!(
        input_query,
        &String::from_utf8_lossy(&qr.serialize().unwrap())
    );
}
