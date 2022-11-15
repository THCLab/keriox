use chrono::{DateTime, FixedOffset};
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use super::{key_state_notice::KeyStateNotice, Timestamped};
#[cfg(feature = "oobi")]
use crate::oobi::{EndRole, LocationScheme};
use crate::{
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    event_message::{
        dummy_event::DummyEventMessage,
        signature::{Nontransferable, Signature, SignerData},
        Digestible, EventTypeTag, SaidEvent, Typeable,
    },
    event_parsing::primitives::CesrPrimitive,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::QueryError,
    sai::derivation::SelfAddressing,
};

#[derive(Clone, PartialEq, Debug)]
pub enum ReplyRoute {
    Ksn(IdentifierPrefix, KeyStateNotice),
    #[cfg(feature = "oobi")]
    LocScheme(LocationScheme),
    #[cfg(feature = "oobi")]
    EndRoleAdd(EndRole),
    #[cfg(feature = "oobi")]
    EndRoleCut(EndRole),
}

impl Serialize for ReplyRoute {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut em = serializer.serialize_struct("ReplyRoute", 2)?;
        match self {
            ReplyRoute::Ksn(id, ksn) => {
                em.serialize_field("r", &format!("/ksn/{}", id.to_str()))?;
                em.serialize_field("a", &ksn)?;
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::LocScheme(loc_scheme) => {
                em.serialize_field("r", "/loc/scheme")?;
                em.serialize_field("a", &loc_scheme)?;
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::EndRoleAdd(end_role) => {
                em.serialize_field("r", "/end/role/add")?;
                em.serialize_field("a", &end_role)?;
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::EndRoleCut(end_role) => {
                em.serialize_field("r", "/end/role/cut")?;
                em.serialize_field("a", &end_role)?;
            }
        };
        em.end()
    }
}

impl<'de> Deserialize<'de> for ReplyRoute {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum ReplyType {
            K(KeyStateNotice),
            #[cfg(feature = "oobi")]
            L(LocationScheme),
            #[cfg(feature = "oobi")]
            R(EndRole),
        }
        #[derive(Debug, Deserialize)]
        struct Mapping {
            #[serde(rename = "r")]
            tag: String,
            #[serde(rename = "a")]
            reply_data: ReplyType,
        }

        let Mapping { tag, reply_data } = Mapping::deserialize(deserializer)?;

        if let Some(id_prefix) = tag.strip_prefix("/ksn/") {
            let id: IdentifierPrefix = id_prefix.parse().map_err(de::Error::custom)?;
            let ksn = if let ReplyType::K(ksn) = reply_data {
                Ok(ksn)
            } else {
                Err(Error::SemanticError("Wrong route".into())).map_err(de::Error::custom)
            }?;
            Ok(ReplyRoute::Ksn(id, ksn))
        } else {
            match (&tag[..], reply_data) {
                #[cfg(feature = "oobi")]
                ("/loc/scheme", ReplyType::L(loc_scheme)) => Ok(ReplyRoute::LocScheme(loc_scheme)),
                #[cfg(feature = "oobi")]
                ("/end/role/add", ReplyType::R(end_role)) => Ok(ReplyRoute::EndRoleAdd(end_role)),
                #[cfg(feature = "oobi")]
                ("/end/role/cut", ReplyType::R(end_role)) => Ok(ReplyRoute::EndRoleCut(end_role)),
                _ => Err(Error::SemanticError("Wrong route".into())).map_err(de::Error::custom),
            }
        }
    }
}

pub type ReplyEvent = EventMessage<SaidEvent<Timestamped<ReplyRoute>>>;

impl Typeable for ReplyRoute {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Rpy
    }
}

impl ReplyEvent {
    pub fn new_reply(
        route: ReplyRoute,
        self_addressing: SelfAddressing,
        serialization: SerializationFormats,
    ) -> Result<ReplyEvent, Error> {
        let env = Timestamped::new(route);
        env.to_message(serialization, self_addressing)
    }
}

impl ReplyEvent {
    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.event.content.timestamp
    }

    pub fn get_route(&self) -> ReplyRoute {
        self.event.content.data.clone()
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        match &self.event.content.data {
            ReplyRoute::Ksn(_, ksn) => ksn.state.prefix.clone(),
            #[cfg(feature = "oobi")]
            ReplyRoute::LocScheme(loc) => loc.get_eid(),
            #[cfg(feature = "oobi")]
            ReplyRoute::EndRoleAdd(endrole) | ReplyRoute::EndRoleCut(endrole) => {
                endrole.cid.clone()
            }
        }
    }
}

impl ReplyEvent {
    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy = DummyEventMessage::dummy_event(
            self.event.clone(),
            self.serialization_info.kind,
            self.event.get_digest().derivation,
        )?
        .serialize()?;
        self.event
            .get_digest()
            .verify_binding(&dummy)
            .then(|| ())
            .ok_or(Error::IncorrectDigest)
    }
}

#[cfg(feature = "query")]
pub fn bada_logic(new_rpy: &SignedReply, old_rpy: &SignedReply) -> Result<(), QueryError> {
    use std::cmp::Ordering;

    // helper function for reply timestamps checking
    fn check_dts(new_rpy: &ReplyEvent, old_rpy: &ReplyEvent) -> Result<(), QueryError> {
        let new_dt = new_rpy.get_timestamp();
        let old_dt = old_rpy.get_timestamp();
        if new_dt >= old_dt {
            Ok(())
        } else {
            Err(QueryError::StaleRpy.into())
        }
    }
    match new_rpy.signature.clone() {
        Signature::Transferable(SignerData::EventSeal(seal), _sigs) => {
            // A) If sn (sequence number) of last (if forked) Est evt that provides
            //  keys for signature(s) of new is greater than sn of last Est evt
            //  that provides keys for signature(s) of old.

            //  Or

            //  B) If sn of new equals sn of old And date-time-stamp of new is
            //     greater than old

            // check sns
            let new_sn = seal.sn;
            let old_sn: u64 =
                if let Signature::Transferable(SignerData::EventSeal(ref old_seal), _) =
                    old_rpy.signature
                {
                    let seal = old_seal.clone();
                    seal.sn
                } else {
                    return Err(QueryError::Error(
                        "Improper signature type. Should be transferable.".into(),
                    )
                    .into());
                };

            match old_sn.cmp(&new_sn) {
                Ordering::Less => Ok(()),
                Ordering::Equal => check_dts(&new_rpy.reply, &old_rpy.reply),
                Ordering::Greater => Err(QueryError::StaleRpy.into()),
            }
        }
        Signature::Transferable(_, _sigs) => {
            todo!()
        }
        Signature::NonTransferable(_) => {
            //  If date-time-stamp of new is greater than old
            check_dts(&new_rpy.reply, &old_rpy.reply)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReply {
    pub reply: ReplyEvent,
    pub signature: Signature,
}

impl SignedReply {
    pub fn new_nontrans(
        reply: ReplyEvent,
        signer: BasicPrefix,
        signature: SelfSigningPrefix,
    ) -> Self {
        let signature =
            Signature::NonTransferable(Nontransferable::Couplet(vec![(signer, signature)]));
        Self { reply, signature }
    }

    pub fn new_trans(
        envelope: ReplyEvent,
        signer_seal: EventSeal,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        let signature = Signature::Transferable(SignerData::EventSeal(signer_seal), signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}

#[test]
pub fn reply_parse() {
    use std::convert::TryFrom;

    use crate::{
        event_message::signed_event_message::{Message, Op},
        event_parsing::message::signed_message,
    };

    let rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EYFMuK9IQmHvq9KaJ1r67_MMCq5GnQEgLyN9YPamR3r0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAAAwEOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30-AABAAYsqumzPM0bIo04gJ4Ln0zAOsGVnjHZrFjjjS49hGx_nQKbXuD1D4J_jNoEa4TPtPDnQ8d0YcJ4TIRJb-XouJBg"#;

    let parsed = signed_message(rpy.as_bytes()).unwrap().1;
    let deserialized_rpy = Message::try_from(parsed).unwrap();

    assert!(matches!(deserialized_rpy, Message::Op(Op::Reply(_))));
}

#[cfg(feature = "oobi")]
#[test]
pub fn oobi_reply_parse() {
    use std::convert::TryFrom;

    use crate::{
        event_message::signed_event_message::{Message, Op},
        event_parsing::message::{signed_event_stream, signed_message},
    };

    let endrole = br#"{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let parsed = signed_message(endrole).unwrap().1;
    let deserialized_rpy = Message::try_from(parsed).unwrap();

    if let Message::Op(Op::Reply(reply)) = deserialized_rpy {
        assert!(matches!(reply.reply.get_route(), ReplyRoute::EndRoleAdd(_)));
    } else {
        assert!(false)
    };

    let endrole = br#"{"v":"KERI10JSON000113_","t":"rpy","d":"EwZH6wJVwwqb2tmhYKYa-GyiO75k4MqkuMKyG2XWpP7Y","dt":"2021-01-01T00:00:01.000000+00:00","r":"/end/role/cut","a":{"cid":"Bsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI","role":"watcher","eid":"BXphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs"}}-VAi-CABBsr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI0BUrzk2jcq5YtdMuW4s4U6FuGrfHNZZAn4pzfzzsEcfIsgfMbhJ1ozpWlYPYdR3wbryWUkxfWqtbNwDWlBdTblAQ"#;
    let parsed = signed_message(endrole).unwrap().1;
    let deserialized_rpy = Message::try_from(parsed).unwrap();

    if let Message::Op(Op::Reply(reply)) = deserialized_rpy {
        assert!(matches!(reply.reply.get_route(), ReplyRoute::EndRoleCut(_)));
    } else {
        assert!(false)
    };

    let body = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let stream = signed_event_stream(body).unwrap();

    assert_eq!(stream.1.len(), 3);
}
