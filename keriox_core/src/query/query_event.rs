use cesrox::{payload::Payload, ParsedData};
use said::derivation::HashFunctionCode;
use said::version::format::SerializationFormats;
use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event_message::{
        msg::KeriEvent,
        signature::{signatures_into_groups, Nontransferable, Signature, SignerData},
        timestamped::Timestamped,
        EventTypeTag, Typeable,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::mailbox::QueryArgsMbx,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum QueryRoute {
    #[serde(rename = "logs")]
    Logs {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: LogsQueryArgs,
    },
    #[serde(rename = "ksn")]
    Ksn {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: LogsQueryArgs,
    },
    #[cfg(feature = "mailbox")]
    #[serde(rename = "mbx")]
    Mbx {
        #[serde(rename = "rr")]
        reply_route: String,
        #[serde(rename = "q")]
        args: QueryArgsMbx,
    },
}

impl QueryRoute {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            // QueryRoute::Log { ref args, .. } => args.i.clone(),
            QueryRoute::Ksn { ref args, .. } => args.i.clone(),
            QueryRoute::Logs { ref args, .. } => args.i.clone(),
            #[cfg(feature = "mailbox")]
            QueryRoute::Mbx { ref args, .. } => args.i.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogQueryArgs {
    pub i: IdentifierPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct LogsQueryArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s: Option<u64>,
    pub i: IdentifierPrefix,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<IdentifierPrefix>,
}

pub type QueryEvent = KeriEvent<Timestamped<QueryRoute>>;

impl QueryEvent {
    pub fn new_query(
        route: QueryRoute,
        serialization_format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> Result<Self, Error> {
        let env = Timestamped::new(route);
        KeriEvent::new(serialization_format, derivation.into(), env)
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.data.data.get_prefix()
    }

    pub fn get_route(&self) -> &QueryRoute {
        &self.data.data
    }
}

impl Typeable for QueryRoute {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Qry
    }
}

pub type SignedKelQuery = SignedQuery<QueryEvent>;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedQuery<D> {
    pub query: D,
    pub signature: Signature,
}

impl<D> SignedQuery<D> {
    pub fn new_nontrans(query: D, signer: BasicPrefix, signature: SelfSigningPrefix) -> Self {
        let signature =
            Signature::NonTransferable(Nontransferable::Couplet(vec![(signer, signature)]));
        Self { query, signature }
    }

    pub fn new_trans(
        query: D,
        signer_id: IdentifierPrefix,
        signatures: Vec<IndexedSignature>,
    ) -> Self {
        let signature =
            Signature::Transferable(SignerData::LastEstablishment(signer_id), signatures);
        Self { query, signature }
    }
}

impl<D> SignedQuery<KeriEvent<D>>
where
    D: Clone + Serialize + Typeable<TypeTag = EventTypeTag>,
{
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let payload: Payload = self.query.clone().into();
        let attachments = signatures_into_groups(&[self.signature.clone()]);
        ParsedData {
            payload,
            attachments,
        }
        .to_cesr()
        .map_err(|_e| Error::CesrError)
    }
}

#[test]
pub fn signed_query_parse() {
    use cesrox::parse;
    use std::convert::TryFrom;

    use crate::event_message::signed_event_message::{Message, Op};

    let input_query = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVwZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-HABEFyzzg2Mp5A3ecChc6AhSLTQssBZAmNvPnGxjJyHxl4F-AABAAB1DuEfnZZ6juMZDYiodcWiIqdjuEE-QzdORp-DbxdDN_GG84x_NA1rSc5lPfPQQkQkxI862_XjyZLHyClVTLoD"#;

    let parsed = parse(input_query).unwrap().1;
    let deserialized_qry = Message::try_from(parsed).unwrap();

    match deserialized_qry {
        Message::Notice(_) => todo!(),
        Message::Op(Op::Query(sq)) => {
            assert!(matches!(
                sq.signature,
                Signature::Transferable(SignerData::LastEstablishment(_), _)
            ))
        }
        _ => unreachable!(),
    };
}

#[test]
fn test_query_deserialize() {
    let input_query = r#"{"v":"KERI10JSON000105_","t":"qry","d":"EHtaQHsKzezkQUEYjMjEv6nIf4AhhR9Zy6AvcfyGCXkI","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s":0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();
    assert!(matches!(qr.data.data, QueryRoute::Logs { .. },));

}

#[test]
fn test_query_mbx_deserialize() {
    use crate::query::mailbox::QueryTopics;
    let input_query = r#"{"v":"KERI10JSON000165_","t":"qry","d":"EKrOiJOMKnTLvJJz0j9hJ5acANkr_DFhVp6HgfjZLOUR","dt":"2022-10-25T09:53:04.454094+00:00","r":"mbx","rr":"","q":{"pre":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","src":"BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha"}}"#; //-VAj-HABEKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4-AABAAAQY9eL1n96itQTvVTEdKjb-xYFWy-SYylQopNeYpYEW9bJ96h4deDboGOUCzVUCQrZ2kt2UNFL3xSJn4ieWLAC"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();

    assert!(matches!(
        qr.data.data,
        QueryRoute::Mbx {
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
