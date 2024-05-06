use cesrox::{payload::Payload, ParsedData};
use said::derivation::HashFunctionCode;
use said::version::format::SerializationFormats;
use serde::{Deserialize, Serialize};

use crate::{
    actor::{parse_query_stream, prelude::Message},
    error::Error,
    event_message::{
        msg::KeriEvent,
        signature::{signatures_into_groups, Nontransferable, Signature, SignerData},
        signed_event_message::Op,
        timestamped::Timestamped,
        EventTypeTag, Typeable,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::mailbox::QueryArgsMbx,
};

use super::mailbox::{MailboxQuery, SignedMailboxQuery};

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
}

impl QueryRoute {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            // QueryRoute::Log { ref args, .. } => args.i.clone(),
            QueryRoute::Ksn { ref args, .. } => args.i.clone(),
            QueryRoute::Logs { ref args, .. } => args.i.clone(),
            // #[cfg(feature = "mailbox")]
            // QueryRoute::Mbx { ref args, .. } => args.i.clone(),
        }
    }
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

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SignedQueryMessage {
    KelQuery(SignedKelQuery),
    MailboxQuery(SignedMailboxQuery),
}

impl SignedQueryMessage {
    pub fn signature(&self) -> Signature {
        match self {
            SignedQueryMessage::KelQuery(qry) => qry.signature.clone(),
            SignedQueryMessage::MailboxQuery(qry) => qry.signature.clone(),
        }
    }

    pub fn prefix(&self) -> IdentifierPrefix {
        match self {
            SignedQueryMessage::KelQuery(qry) => qry.query.get_prefix(),
            SignedQueryMessage::MailboxQuery(qry) => match &qry.query.data.data {
                super::mailbox::MailboxRoute::Mbx {
                    reply_route: _,
                    args,
                } => args.i.clone(),
            },
        }
    }
}

impl From<SignedQueryMessage> for Message {
    fn from(value: SignedQueryMessage) -> Self {
        Message::Op(Op::Query(value))
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

    let input_query = br#"{"v":"KERI10JSON0000ff_","t":"qry","d":"EKZbZZs0KweJm_VbpHBqM6Uvn0tCOoQRQ4okoyoKKXVH","dt":"2024-02-29T13:37:25.671274+00:00","r":"logs","rr":"","q":{"i":"EAz8-amlMgzWkUAcGLzPR5SZ57K0fLaG6eV3DK9SHadw","src":"BLogequWU0j7imRMuDrPChX9BCWuhZJVWawP9zuibmlk"}}-HABEMnw5Z0A0S_ab2l3LJ5qwgf0MgfFFCrWHIl4iZNvmFUO-AABAACGk8GcwX1BXQ2KKIncFH1h3tpSDd4rfU4zUC0gEIIwDv2IPnL7WlvyIxcKcO7yv17FbfX1DpWAiHfCEWZlrWMP"#;

    let parsed = parse(input_query).unwrap().1;
    let deserialized_qry = Message::try_from(parsed).unwrap();

    match deserialized_qry {
        Message::Notice(_) => todo!(),
        Message::Op(Op::Query(sq)) => {
            assert!(matches!(
                sq.signature(),
                Signature::Transferable(SignerData::LastEstablishment(_), _)
            ))
        }
        _ => unreachable!(),
    };
}
#[test]
fn test_query_deserialize2() {
    let input_query = r#"{"v":"KERI10JSON00018e_","t":"qry","d":"EKzixWgm8tbppUuomNpgtXl4ACJoGvCbN06AIx_u3dfo","dt":"2024-05-06T14:32:59.886055+00:00","r":"mbx","rr":"","q":{"pre":"EASI5JckejnF6SAQxKSz2DHJy_oE5MKGS17GypPJ34Yd","topics":{"/receipt":0,"/replay":0,"/reply":0,"/multisig":0,"/credential":0,"/delegate":0},"i":"EASI5JckejnF6SAQxKSz2DHJy_oE5MKGS17GypPJ34Yd","src":"BKCOy7psittpzQMUkJ3hkdtk0x5PsyCthc5cvDcbwhn3"}}"#; //-HABEASI5JckejnF6SAQxKSz2DHJy_oE5MKGS17GypPJ34Yd-AABAAA5MnFbTLKYSRzXG0wtfuuDj80Um7h_tLhoWDGKam9Q89Ifr3NbE01XSONXZ2gWUL4YPEaQRI5VYAR6brZVOVQF"#;
    let qr: MailboxQuery = serde_json::from_str(input_query).unwrap();
}

#[test]
fn test_query_deserialize() {
    let input_query = r#"{"v":"KERI10JSON000105_","t":"qry","d":"EHtaQHsKzezkQUEYjMjEv6nIf4AhhR9Zy6AvcfyGCXkI","dt":"2021-01-01T00:00:00.000000+00:00","r":"logs","rr":"","q":{"s":0,"i":"EIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}"#;
    let qr: QueryEvent = serde_json::from_str(input_query).unwrap();
    assert!(matches!(qr.data.data, QueryRoute::Logs { .. },));
}
