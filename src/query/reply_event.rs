
use chrono::{DateTime, FixedOffset};
use serde::{de, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    event_message::{
        dummy_event::DummyEventMessage, signature::Signature, Digestible, EventTypeTag, SaidEvent,
        Typeable,
    },
    oobi::{EndRole, LocationScheme},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfSigningPrefix},
};

use super::{key_state_notice::KeyStateNotice, Timestamped};

#[derive(Clone, PartialEq, Debug)]
pub enum ReplyRoute {
    Ksn(IdentifierPrefix, KeyStateNotice),
    LocScheme(LocationScheme),
    EndRole(EndRole),
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
            ReplyRoute::LocScheme(loc_scheme) => {
                em.serialize_field("r", "/loc/scheme")?;
                em.serialize_field("a", &loc_scheme)?;
            }
            ReplyRoute::EndRole(end_role) => {
                em.serialize_field("r", "/end/role/add")?;
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
        struct Mapping {
            #[serde(rename = "r")]
            tag: String,
            #[serde(rename = "a")]
            ksn: Option<KeyStateNotice>,
            #[serde(rename = "a")]
            loc_scheme: Option<LocationScheme>,
            #[serde(rename = "a")]
            end_role: Option<EndRole>,
        }

        let Mapping {
            tag,
            ksn,
            loc_scheme,
            end_role,
        } = Mapping::deserialize(deserializer)?;

        if let Some(id_prefix) = tag.strip_prefix("/ksn/") {
            let id: IdentifierPrefix = id_prefix.parse().map_err(de::Error::custom)?;
            Ok(ReplyRoute::Ksn(id, ksn.unwrap()))
        } else {
            match &tag[..] {
                "/loc/scheme" => Ok(ReplyRoute::LocScheme(loc_scheme.unwrap())),
                "/end/role/add" => Ok(ReplyRoute::EndRole(end_role.unwrap())),
                _ => Err(Error::SemanticError("Unknown route".into())).map_err(de::Error::custom),
            }
        }
    }
}



pub type ReplyEvent = EventMessage<SaidEvent<Timestamped<ReplyRoute>>>;
// pub type ReplyKsnEvent = ReplyEvent<KeyStateNotice>;
// pub type Reply = Envelope<ReplyData>;
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
        env.to_message(serialization, &self_addressing)
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
            ReplyRoute::LocScheme(loc) => loc.get_eid(),
            ReplyRoute::EndRole(endrole) => endrole.cid.clone(),
        }
    }
}

impl ReplyEvent {
    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy = DummyEventMessage::dummy_event(
            self.event.clone(),
            self.serialization_info.kind,
            &self.event.get_digest().derivation,
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
pub fn bada_logic(new_rpy: &SignedReply, old_rpy: &SignedReply) -> Result<(), Error> {
    use std::cmp::Ordering;

    use crate::query::QueryError;

    // helper function for reply timestamps checking
    fn check_dts(new_rpy: &ReplyEvent, old_rpy: &ReplyEvent) -> Result<(), Error> {
        let new_dt = new_rpy.get_timestamp();
        let old_dt = old_rpy.get_timestamp();
        if new_dt >= old_dt {
            Ok(())
        } else {
            Err(QueryError::StaleRpy.into())
        }
    }
    match new_rpy.signature.clone() {
        Signature::Transferable(seal, _sigs) => {
            // A) If sn (sequence number) of last (if forked) Est evt that provides
            //  keys for signature(s) of new is greater than sn of last Est evt
            //  that provides keys for signature(s) of old.

            //  Or

            //  B) If sn of new equals sn of old And date-time-stamp of new is
            //     greater than old

            // check sns
            let new_sn = seal.sn;
            let old_sn: u64 = if let Signature::Transferable(ref seal, _) = old_rpy.signature {
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
        Signature::NonTransferable(_bp, _sig) => {
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
        let signature = Signature::NonTransferable(signer, signature);
        Self {
            reply,
            signature,
        }
    }

    pub fn new_trans(
        envelope: ReplyEvent,
        signer_seal: EventSeal,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        let signature = Signature::Transferable(signer_seal, signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}

#[test]
pub fn reply_parse() {
    use crate::event_parsing::message::signed_message;
    use crate::event_message::signed_event_message::Message;
    use std::convert::TryFrom;
    let rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EYFMuK9IQmHvq9KaJ1r67_MMCq5GnQEgLyN9YPamR3r0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAAAwEOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30-AABAAYsqumzPM0bIo04gJ4Ln0zAOsGVnjHZrFjjjS49hGx_nQKbXuD1D4J_jNoEa4TPtPDnQ8d0YcJ4TIRJb-XouJBg"#;

    let parsed = signed_message(rpy.as_bytes()).unwrap().1;
    let deserialized_rpy = Message::try_from(parsed).unwrap();

    assert!(matches!(deserialized_rpy, Message::Reply(_)));

}