use crate::event_message::keri_version::KeriVersion;
use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use serde::{ser::SerializeStruct, Deserialize, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

use crate::state::IdentifierState;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KeyStateNotice {
    /// The KERI version of the notice, written as `vn: [major, minor]`
    /// like keripy's key state records; a notice is a field map inside a
    /// reply, not a message with a version string of its own.
    #[serde(rename = "vn", deserialize_with = "version_number::deserialize")]
    pub version: KeriVersion,

    #[serde(flatten)]
    pub state: IdentifierState,

    /// The first-seen number of the latest event: its position in the
    /// order this node accepted the KEL's events, disputed ones included.
    #[serde(rename = "f", with = "SerHex::<Compact>")]
    pub first_seen: u64,

    #[serde(rename = "dt")]
    pub timestamp: DateTime<FixedOffset>,

    #[serde(rename = "c")]
    config: Vec<String>,
}

impl Serialize for KeyStateNotice {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut em = serializer.serialize_struct("Envelope", 17)?;
        em.serialize_field("vn", &version_number::Pair::from(self.version))?;
        em.serialize_field("i", &self.state.prefix)?;
        // Sequence numbers are hex, as everywhere in KERI and as they are read.
        em.serialize_field("s", &format!("{:x}", self.state.sn))?;
        // An inception has no prior event: the empty string, as in keripy.
        em.serialize_field(
            "p",
            &self
                .state
                .last_previous
                .as_ref()
                .map_or(String::new(), |p| p.said.to_string()),
        )?;
        em.serialize_field("d", &self.state.last_event_digest)?;
        em.serialize_field("f", &format!("{:x}", self.first_seen))?;
        em.serialize_field(
            "dt",
            &self.timestamp.to_rfc3339_opts(SecondsFormat::Micros, false),
        )?;
        em.serialize_field("et", &self.state.last_event_type)?;
        em.serialize_field("kt", &self.state.current.threshold)?;
        em.serialize_field("k", &self.state.current.public_keys)?;
        em.serialize_field("nt", &self.state.current.next_keys_data.threshold)?;
        em.serialize_field("n", &self.state.current.next_keys_data.next_keys_hashes())?;
        em.serialize_field("bt", &self.state.witness_config.tally)?;
        em.serialize_field("b", &self.state.witness_config.witnesses)?;
        em.serialize_field("c", &self.config)?;
        em.serialize_field("ee", &self.state.last_est)?;
        em.serialize_field("di", &self.state.delegator.clone().unwrap_or_default())?;
        em.end()
    }
}

impl KeyStateNotice {
    /// The key state notice of `state` in `version`, whose latest event
    /// this node saw as the `first_seen`th event of the KEL.
    pub fn new_ksn(
        state: IdentifierState,
        first_seen: u64,
        version: KeriVersion,
    ) -> Self {
        let dt: DateTime<FixedOffset> = DateTime::from(Utc::now());

        KeyStateNotice {
            version,
            timestamp: dt,
            state,
            first_seen,
            config: vec![],
        }
    }
}


/// `vn`: a KERI version as `[major, minor]`.
mod version_number {
    use serde::{de, Deserialize, Deserializer, Serialize};

    use crate::event_message::keri_version::KeriVersion;

    #[derive(Serialize, Deserialize)]
    pub struct Pair(u8, u8);

    impl From<KeriVersion> for Pair {
        fn from(version: KeriVersion) -> Self {
            match version {
                KeriVersion::V1_0 => Pair(1, 0),
                KeriVersion::V2_0 => Pair(2, 0),
            }
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<KeriVersion, D::Error> {
        match Pair::deserialize(d)? {
            Pair(1, 0) => Ok(KeriVersion::V1_0),
            Pair(2, 0) => Ok(KeriVersion::V2_0),
            Pair(major, minor) => Err(de::Error::custom(format!(
                "unknown KERI version {major}.{minor}"
            ))),
        }
    }
}

/// A KEL and the key state notices its controller signs of it, for tests.
#[cfg(all(test, feature = "query"))]
pub(crate) mod fixtures {
    use said::{derivation::HashFunctionCode, version::format::SerializationFormats};

    use super::KeyStateNotice;
    use crate::{
        event::sections::seal::EventSeal,
        event_message::{
            cesr_adapter::parse_cesr_stream,
            event_msg_builder::EventMsgBuilder,
            keri_version::KeriVersion,
            signed_event_message::{Message, Op, SignedEventMessage},
            EventTypeTag,
        },
        prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
        query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        signer::Signer,
        state::IdentifierState,
    };

    /// An inception, interactions at 1 to 3, a rotation at 4 and
    /// interactions at 5 to 8.
    pub struct Kel {
        pub id: IdentifierPrefix,
        pub events: Vec<SignedEventMessage>,
        keys: Vec<Signer>,
    }

    /// The establishment event in force at `sn` and the index of its key.
    fn establishment(sn: u64) -> (u64, usize) {
        if sn >= 4 {
            (4, 1)
        } else {
            (0, 0)
        }
    }

    pub fn kel() -> Kel {
        let keys: Vec<Signer> = (0..3).map(|_| Signer::new()).collect();
        let key = |i: usize| BasicPrefix::Ed25519(keys[i].public_key());
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(0)])
            .with_next_keys(vec![key(1)])
            .build()
            .unwrap();
        let id = icp.data.get_prefix();
        let mut events = vec![icp];
        for sn in 1..=8 {
            let prior = events.last().unwrap().digest().unwrap();
            let builder = if sn == 4 {
                EventMsgBuilder::new(EventTypeTag::Rot)
                    .with_keys(vec![key(1)])
                    .with_next_keys(vec![key(2)])
            } else {
                EventMsgBuilder::new(EventTypeTag::Ixn)
            };
            events.push(
                builder
                    .with_prefix(&id)
                    .with_sn(sn)
                    .with_previous_event(&prior)
                    .build()
                    .unwrap(),
            );
        }
        let events = events
            .into_iter()
            .map(|event| {
                let signer = &keys[establishment(event.data.get_sn()).1];
                let sig = SelfSigningPrefix::Ed25519Sha512(
                    signer.sign(event.encode().unwrap()).unwrap(),
                );
                event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)
            })
            .collect();
        Kel { id, events, keys }
    }

    /// The controller's notice of its key state at `sn`, signed with the
    /// keys in force there.
    pub fn ksn_reply(kel: &Kel, sn: u64) -> SignedReply {
        let state = kel.events[..=sn as usize]
            .iter()
            .fold(IdentifierState::default(), |state, event| {
                state.apply(&event.event_message).unwrap()
            });
        let ksn = KeyStateNotice::new_ksn(state, sn, KeriVersion::V1_0);
        let reply = ReplyEvent::new_reply(
            ReplyRoute::Ksn(kel.id.clone(), ksn),
            &kel.id,
            KeriVersion::V1_0,
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let (est_sn, key) = establishment(sn);
        let sig = SelfSigningPrefix::Ed25519Sha512(
            kel.keys[key].sign(reply.encode().unwrap()).unwrap(),
        );
        let est = &kel.events[est_sn as usize].event_message;
        let signed = SignedReply::new_trans(
            reply,
            EventSeal::new(kel.id.clone(), est_sn, est.digest().unwrap()),
            vec![IndexedSignature::new_both_same(sig, 0)],
        );
        // As read from the wire: the timestamps of a freshly built reply
        // carry nanoseconds its encoding does not.
        let cesr = Message::Op(Op::Reply(signed)).to_cesr().unwrap();
        match Message::try_from(parse_cesr_stream(&cesr).unwrap()).unwrap() {
            Message::Op(Op::Reply(reply)) => reply,
            other => panic!("not a reply: {other:?}"),
        }
    }
}
