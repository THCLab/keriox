use crate::event_message::keri_version::KeriVersion;
use cesrox::primitives::CesrPrimitive;
use chrono::{DateTime, FixedOffset};
use said::derivation::HashFunctionCode;
use said::version::format::SerializationFormats;
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use super::key_state_notice::KeyStateNotice;
#[cfg(feature = "oobi")]
use crate::oobi::{EndRole, LocationScheme, OobiUrl, OobiUrls, Role};
use crate::{
    error::Error,
    event::sections::seal::EventSeal,
    event_message::{
        msg::KeriEvent,
        signature::{Nontransferable, Signature, SignerData},
        timestamped::Timestamped,
        EventTypeTag, Typeable,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::QueryError,
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
    /// `/oobi/process`: a url OOBI.
    #[cfg(feature = "oobi")]
    OobiProcess(OobiUrl),
    /// `/oobi/{role}`: the urls of the providers of a role.
    #[cfg(feature = "oobi")]
    OobiUrls(Role, OobiUrls),
    /// `/oobi/{aid}/{role}`: the location of an endpoint provider of
    /// `aid` in a role, an end role and its location in one reply.
    #[cfg(feature = "oobi")]
    OobiEndpoint(IdentifierPrefix, Role, LocationScheme),
}

impl ReplyRoute {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match &self {
            ReplyRoute::Ksn(_, ksn) => ksn.state.prefix.clone(),
            #[cfg(feature = "oobi")]
            ReplyRoute::LocScheme(loc) => loc.get_eid(),
            #[cfg(feature = "oobi")]
            ReplyRoute::EndRoleAdd(endrole) | ReplyRoute::EndRoleCut(endrole) => {
                endrole.cid.clone()
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiProcess(oobi) => oobi.i.clone(),
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiUrls(_, oobi) => oobi.cid.clone(),
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiEndpoint(aid, _, _) => aid.clone(),
        }
    }
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
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiProcess(oobi) => {
                em.serialize_field("r", "/oobi/process")?;
                em.serialize_field("a", &oobi)?;
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiUrls(role, oobi) => {
                em.serialize_field("r", &format!("/oobi/{}", role.as_str()))?;
                em.serialize_field("a", &oobi)?;
            }
            #[cfg(feature = "oobi")]
            ReplyRoute::OobiEndpoint(aid, role, loc) => {
                em.serialize_field("r", &format!("/oobi/{}/{}", aid.to_str(), role.as_str()))?;
                em.serialize_field("a", &loc)?;
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
            #[cfg(feature = "oobi")]
            U(OobiUrl),
            #[cfg(feature = "oobi")]
            M(OobiUrls),
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
            let ksn = match reply_data {
                ReplyType::K(ksn) => ksn,
                _ => {
                    return Err(de::Error::custom("Wrong route"));
                }
            };
            Ok(ReplyRoute::Ksn(id, ksn))
        } else if let Some(path) = tag.strip_prefix("/oobi/") {
            #[cfg(feature = "oobi")]
            {
                let role = |role: &str| role.parse::<Role>().map_err(de::Error::custom);
                let segments: Vec<&str> = path.split('/').collect();
                match (&segments[..], reply_data) {
                    (["process"], ReplyType::U(oobi)) => Ok(ReplyRoute::OobiProcess(oobi)),
                    ([name], ReplyType::M(oobi)) => Ok(ReplyRoute::OobiUrls(role(name)?, oobi)),
                    ([aid, name], ReplyType::L(loc)) => Ok(ReplyRoute::OobiEndpoint(
                        aid.parse().map_err(de::Error::custom)?,
                        role(name)?,
                        loc,
                    )),
                    _ => Err(de::Error::custom("Wrong route")),
                }
            }
            #[cfg(not(feature = "oobi"))]
            {
                let _ = (path, reply_data);
                Err(de::Error::custom("Wrong route"))
            }
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

pub type ReplyEvent = KeriEvent<Timestamped<ReplyRoute>>;

impl Typeable for ReplyRoute {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Rpy
    }
}

impl ReplyEvent {
    /// A reply sent by `sender`, in `version`.
    pub fn new_reply(
        route: ReplyRoute,
        sender: &IdentifierPrefix,
        version: KeriVersion,
        self_addressing: HashFunctionCode,
        serialization: SerializationFormats,
    ) -> ReplyEvent {
        let env = Timestamped::sent(route, sender, version);
        KeriEvent::new(version, serialization, self_addressing.into(), env)
    }
}

impl ReplyEvent {
    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.data.timestamp
    }

    pub fn get_route(&self) -> ReplyRoute {
        self.data.data.clone()
    }

    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.data.data.get_prefix()
    }
}

#[cfg(feature = "query")]
pub fn bada_logic(new_rpy: &SignedReply, old_rpy: &SignedReply) -> Result<(), QueryError> {
    use std::cmp::Ordering;

    // An update needs a later date-time than the prior's. The prior itself,
    // sent again, changes nothing and is let through.
    fn check_dts(new_rpy: &ReplyEvent, old_rpy: &ReplyEvent) -> Result<(), QueryError> {
        let new_dt = new_rpy.get_timestamp();
        let old_dt = old_rpy.get_timestamp();
        if new_dt > old_dt || new_rpy == old_rpy {
            Ok(())
        } else {
            Err(QueryError::StaleRpy)
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
                    ));
                };

            match old_sn.cmp(&new_sn) {
                Ordering::Less => Ok(()),
                Ordering::Equal => check_dts(&new_rpy.reply, &old_rpy.reply),
                Ordering::Greater => Err(QueryError::StaleRpy),
            }
        }
        // The reply comes from the network: a signer the policy cannot
        // place in its KEL is refused rather than a panic.
        Signature::Transferable(_, _sigs) => Err(QueryError::Error(
            "a transferable reply signature needs an event seal".into(),
        )),
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
        signatures: Vec<IndexedSignature>,
    ) -> Self {
        let signature = Signature::Transferable(SignerData::EventSeal(signer_seal), signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::event_message::cesr_adapter::parse_cesr_stream;

    #[test]
    pub fn reply_parse() {
        use std::convert::TryFrom;

        use crate::event_message::signed_event_message::{Message, Op};

        let kel = crate::query::key_state_notice::fixtures::kel();
        let rpy = Message::Op(Op::Reply(
            crate::query::key_state_notice::fixtures::ksn_reply(&kel, 3),
        ))
        .to_cesr()
        .unwrap();

        let parsed = parse_cesr_stream(&rpy).unwrap();
        let deserialized_rpy = Message::try_from(parsed).unwrap();

        assert!(matches!(deserialized_rpy, Message::Op(Op::Reply(_))));

        // The signer's seal and signatures, read from a -T and a -K group,
        // are written back the same way by default and as one -X group in
        // V2, and read back unchanged from both.
        assert_eq!(deserialized_rpy.to_cesr().unwrap(), rpy);
        let written = deserialized_rpy.to_cesr().unwrap();
        let attachments = parse_cesr_stream(&written).unwrap().attachments;
        assert!(matches!(
            attachments.as_slice(),
            [cesrox::group::Group::TransIdxSigGroups(_)]
        ));
        assert_eq!(
            Message::try_from(parse_cesr_stream(&written).unwrap()).unwrap(),
            deserialized_rpy
        );
    }

    #[cfg(feature = "oobi")]
    #[test]
    pub fn oobi_reply_parse() {
        use std::convert::TryFrom;

        use crate::event_message::cesr_adapter::parse_cesr_stream_many;

        use crate::{
            event_message::signed_event_message::{Message, Op},
            oobi::{EndRole, Role},
            query::reply_event::ReplyRoute,
        };

        let endrole = br#"-_AAACAA{"v":"KERI10JSON000116_","t":"rpy","d":"EMZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-MAhBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BBccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
        let parsed = parse_cesr_stream(endrole).unwrap();
        let deserialized_rpy = Message::try_from(parsed).unwrap();

        if let Message::Op(Op::Reply(reply)) = deserialized_rpy {
            assert!(matches!(reply.reply.get_route(), ReplyRoute::EndRoleAdd(_)));
        } else {
            assert!(false)
        };

        let endrole = br#"-_AAACAA{"v":"KERI10JSON000113_","t":"rpy","d":"EAZH6wJVwwqb2tmhYKYa-GyiO75k4MqkuMKyG2XWpP7Y","dt":"2021-01-01T00:00:01.000000+00:00","r":"/end/role/cut","a":{"cid":"BMr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI","role":"watcher","eid":"BHphIkYC1U2ardvt2kGLThDRh2q9N-yT08WSRlpHwtGs"}}-MAhBMr9jFyYr-wCxJbUJs0smX8UDSDDQUoO4-v_FTApyPvI0BArzk2jcq5YtdMuW4s4U6FuGrfHNZZAn4pzfzzsEcfIsgfMbhJ1ozpWlYPYdR3wbryWUkxfWqtbNwDWlBdTblAQ"#;
        let parsed = parse_cesr_stream(endrole).unwrap();
        let deserialized_rpy = Message::try_from(parsed).unwrap();

        if let Message::Op(Op::Reply(reply)) = deserialized_rpy {
            assert!(matches!(reply.reply.get_route(), ReplyRoute::EndRoleCut(_)));
        } else {
            assert!(false)
        };

        let body = br#"-_AAACAA{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-MAhBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw-_AAACAA{"v":"KERI10JSON0000f8_","t":"rpy","d":"EBSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-MAhBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BBtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg-_AAACAA{"v":"KERI10JSON000116_","t":"rpy","d":"EMZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-MAhBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BBccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
        let stream = parse_cesr_stream_many(body).unwrap();

        assert_eq!(stream.len(), 3);

        let message_box = r#"-_AAACAA{"v":"KERI10JSON000116_","t":"rpy","d":"EGS28iaGy4iDF8w4q7XkXtdnp4lLj97oZ9n-QrZCyt_8","dt":"2023-07-20T12:31:59.458182+00:00","r":"/end/role/add","a":{"cid":"ECQxoxuKOcO7KkbMyKHnbzhi3sWnSJRnGP_-XsL6eamT","role":"messagebox","eid":"BL0RdEFZxEf2wkq7TTYDagcoOxfmWK45enEUQHwLPadJ"}}-XAuECQxoxuKOcO7KkbMyKHnbzhi3sWnSJRnGP_-XsL6eamTMAAAECQxoxuKOcO7KkbMyKHnbzhi3sWnSJRnGP_-XsL6eamT-KAWAABtWkO0ezyg_IC9HeG2rc3wplzAj95lKqVTdnEu46xlELl2M2oHrcpVWC_n1Bg1zgjqAAOeRkBgqdwKha7ZS4IK"#;
        let parsed = parse_cesr_stream(message_box.as_bytes()).unwrap();
        let deserialized_rpy = Message::try_from(parsed).unwrap();

        if let Message::Op(Op::Reply(reply)) = deserialized_rpy {
            assert!(matches!(
                reply.reply.get_route(),
                ReplyRoute::EndRoleAdd(EndRole {
                    eid: _,
                    role: Role::Messagebox,
                    cid: _
                })
            ));
        } else {
            assert!(false)
        };
    }

    /// The OOBI replies of the KERI specification read as their routes and
    /// are written back unchanged.
    #[cfg(feature = "oobi")]
    #[test]
    fn oobi_replies_of_the_specification_round_trip() {
        use super::{ReplyEvent, ReplyRoute};
        use crate::oobi::Role;

        let aid = "EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB";
        let replies = [
            (
                r#"{"v":"KERICAACAAJSONAAFR.","t":"rpy","d":"EPdgmUkvx5o_KRg3elBqj_vSZOFgWI9hCVWO-FfGZz8U","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08-21T17:52:00.000000+00:00","r":"/oobi/process","a":{"i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","url":"https://example.com/witness/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B"}}"#,
                "process",
            ),
            (
                r#"{"v":"KERICAACAAJSONAAIA.","t":"rpy","d":"ELtIQ71PMr9m5a8eYiC39hikuU8yTWoFw1vWjtqbVUX4","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08-21T17:52:00.000000+00:00","r":"/oobi/witness","a":{"cid":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","urls":["https://example.com/witness/wilma/BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","https://example.com/witness/watson/BAPv2MnoiCsgOnklmFyfU07QDK_93NeH9iKfOy8V22aH","https://example.com/witness/winona/BA4PSatfQMw1lYhQoZkSSvOCrE0Sdw1hmmniDL-yDtrB"]}}"#,
                "urls",
            ),
            (
                r#"{"v":"KERICAACAAJSONAAFq.","t":"rpy","d":"EFMQh0w5-AHw-H01DtqEFhAIC6KXbjYvUSOEX6kSPY4j","i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","dt":"2020-08-21T17:52:00.000000+00:00","r":"/oobi/EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB/witness","a":{"eid":"BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","scheme":"https","url":"https://example.com/witness/wilma"}}"#,
                "endpoint",
            ),
        ];
        for (raw, kind) in replies {
            let reply: ReplyEvent = serde_json::from_str(raw).unwrap();
            reply.check_digest().unwrap();
            match (kind, reply.get_route()) {
                ("process", ReplyRoute::OobiProcess(oobi)) => assert_eq!(oobi.i.to_string(), aid),
                ("urls", ReplyRoute::OobiUrls(Role::Witness, oobi)) => {
                    assert_eq!(oobi.urls.len(), 3)
                }
                ("endpoint", ReplyRoute::OobiEndpoint(id, Role::Witness, loc)) => {
                    assert_eq!(id.to_string(), aid);
                    assert_eq!(loc.eid.to_string(), "BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B");
                }
                (kind, route) => panic!("{kind} read as {route:?}"),
            }
            assert_eq!(String::from_utf8(reply.encode().unwrap()).unwrap(), raw);
            assert_eq!(reply.get_prefix().to_string(), aid);
        }
    }

    /// An OOBI route naming a role keriox does not know is refused.
    #[cfg(feature = "oobi")]
    #[test]
    fn an_oobi_reply_for_an_unknown_role_is_refused() {
        use super::ReplyRoute;

        for route in [
            r#"{"r":"/oobi/registrar","a":{"cid":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","urls":[]}}"#,
            r#"{"r":"/oobi/EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB/registrar","a":{"eid":"BGKV6v93ue5L5wsgk75t6j8TcdgABMN9x-eIyPi96J3B","scheme":"https","url":"https://example.com/"}}"#,
            r#"{"r":"/oobi/process/extra","a":{"i":"EPR7FWsN3tOM8PqfMap2FRfF4MFQ4v3ZXjBUcMVtvhmB","url":"https://example.com/"}}"#,
        ] {
            assert!(serde_json::from_str::<ReplyRoute>(route).is_err(), "{route}");
        }
    }
}

