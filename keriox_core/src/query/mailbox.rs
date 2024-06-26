use said::{derivation::HashFunctionCode, sad::SerializationFormats};
use serde::{Deserialize, Serialize};

use crate::{
    event_message::{msg::KeriEvent, timestamped::Timestamped, EventTypeTag, Typeable},
    prefix::IdentifierPrefix,
};

use super::query_event::SignedQuery;

pub type SignedMailboxQuery = SignedQuery<MailboxQuery>;
pub type MailboxQuery = KeriEvent<Timestamped<MailboxRoute>>;

impl MailboxQuery {
    pub fn new_query(
        route: MailboxRoute,
        serialization_format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> Self {
        let env = Timestamped::new(route);
        KeriEvent::new(serialization_format, derivation.into(), env)
    }

    pub fn get_args(&self) -> QueryArgsMbx {
        let MailboxRoute::Mbx {
            reply_route: _,
            args,
        } = &self.data.data;
        args.clone()
    }
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match &self.data.data {
            MailboxRoute::Mbx {
                reply_route: _,
                args,
            } => args.pre.clone(),
        }
    }
}

#[cfg(feature = "mailbox")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum MailboxRoute {
    #[serde(rename = "mbx")]
    Mbx {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: QueryArgsMbx,
    },
}

impl Typeable for MailboxRoute {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Qry
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgsMbx {
    /// Controller's currently used identifier
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
    pub receipt: usize,
    #[serde(rename = "/replay")]
    pub replay: usize,
    #[serde(rename = "/reply")]
    pub reply: usize,
    #[serde(rename = "/multisig")]
    pub multisig: usize,
    #[serde(rename = "/credential")]
    pub credential: usize,
    #[serde(rename = "/delegate")]
    pub delegate: usize,
}

#[test]
fn test_query_mbx_deserialize() {
    use crate::query::mailbox::QueryTopics;
    let input_query = r#"{"v":"KERI10JSON000165_","t":"qry","d":"EKrOiJOMKnTLvJJz0j9hJ5acANkr_DFhVp6HgfjZLOUR","dt":"2022-10-25T09:53:04.454094+00:00","r":"mbx","rr":"","q":{"pre":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","src":"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"}}"#; //-VAj-HABEKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4-AABAAAQY9eL1n96itQTvVTEdKjb-xYFWy-SYylQopNeYpYEW9bJ96h4deDboGOUCzVUCQrZ2kt2UNFL3xSJn4ieWLAC"#;
    let qr: MailboxQuery = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.data.data,
        MailboxRoute::Mbx {
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
    ));

    assert_eq!(input_query, &String::from_utf8_lossy(&qr.encode().unwrap()));
}
