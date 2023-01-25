pub mod cesr_adapter;
pub mod dummy_event;
pub mod event_msg_builder;
pub mod key_event_message;
pub mod msg;
pub mod serializer;
pub mod signature;
pub mod signed_event_message;
pub mod timestamped;

use std::cmp::Ordering;

use crate::{
    error::Error, event::KeyEvent, sai::derivation::SelfAddressing, sai::SelfAddressingPrefix,
};
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize, Serializer};
use version::serialization_info::SerializationFormats;

use self::{dummy_event::DummyEvent, msg::KeriEvent};

pub trait Typeable {
    type TypeTag;
    fn get_type(&self) -> Self::TypeTag;
}
pub trait Digestible {
    fn get_digest(&self) -> SelfAddressingPrefix;
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum EventTypeTag {
    Icp,
    Rot,
    Ixn,
    Dip,
    Drt,
    Rct,
    Exn,
    #[cfg(feature = "query")]
    Rpy,
    #[cfg(feature = "query")]
    Qry,
}

#[derive(Serialize, Deserialize, PartialEq)]
pub struct TimestampedEventMessage {
    pub timestamp: DateTime<Local>,
    pub event_message: KeriEvent<KeyEvent>,
}

impl TimestampedEventMessage {
    pub fn new(event: KeriEvent<KeyEvent>) -> Self {
        Self {
            timestamp: Local::now(),
            event_message: event,
        }
    }
}

impl PartialOrd for TimestampedEventMessage {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(
            match self.event_message.data.get_sn() == other.event_message.data.get_sn() {
                true => Ordering::Equal,
                false => {
                    match self.event_message.data.get_sn() > other.event_message.data.get_sn() {
                        true => Ordering::Greater,
                        false => Ordering::Less,
                    }
                }
            },
        )
    }
}

impl Ord for TimestampedEventMessage {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.event_message.data.get_sn() == other.event_message.data.get_sn() {
            true => Ordering::Equal,
            false => match self.event_message.data.get_sn() > other.event_message.data.get_sn() {
                true => Ordering::Greater,
                false => Ordering::Less,
            },
        }
    }
}

impl Eq for TimestampedEventMessage {}

impl From<TimestampedEventMessage> for KeriEvent<KeyEvent> {
    fn from(event: TimestampedEventMessage) -> KeriEvent<KeyEvent> {
        event.event_message
    }
}

/// WARNING: timestamp will change on conversion to current time
impl From<KeriEvent<KeyEvent>> for TimestampedEventMessage {
    fn from(event: KeriEvent<KeyEvent>) -> TimestampedEventMessage {
        TimestampedEventMessage::new(event)
    }
}

// impl<T: Serialize, D: Clone + Serialize + Digestible + Typeable<TypeTag = T>> KeriEvent<D> {
//     pub fn serialization(&self) -> SerializationFormats {
//         self.serialization_info.kind
//     }

//     /// Serialize
//     ///
//     /// returns the serialized event message
//     /// NOTE: this method, for deserialized events, will be UNABLE to preserve ordering
//     pub fn serialize(&self) -> Result<Vec<u8>, Error> {
//         Ok(self.serialization().encode(self)?)
//     }
// }

#[cfg(test)]
mod tests {
    mod test_utils;

    use self::test_utils::test_mock_event_sequence;
    use super::*;
    use crate::{
        event::{
            event_data::{inception::InceptionEvent, EventData},
            sections::{key_config::nxt_commitment, KeyConfig},
            sections::{threshold::SignatureThreshold, InceptionWitnessConfig},
            KeyEvent,
        },
        keys::{PrivateKey, PublicKey},
        prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        sai::{derivation::SelfAddressing, sad::SAD},
        state::IdentifierState,
    };
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use version::Versional;

    #[test]
    fn basic_create() -> Result<(), Error> {
        // hi Ed!
        let kp0 = Keypair::generate(&mut OsRng);
        let kp1 = Keypair::generate(&mut OsRng);

        // get two ed25519 keypairs
        let pub_key0 = PublicKey::new(kp0.public.to_bytes().to_vec());
        let priv_key0 = PrivateKey::new(kp0.secret.to_bytes().to_vec());
        let (pub_key1, _priv_key1) = (
            PublicKey::new(kp1.public.to_bytes().to_vec()),
            PrivateKey::new(kp1.secret.to_bytes().to_vec()),
        );

        // initial signing key prefix
        let pref0 = BasicPrefix::Ed25519(pub_key0);

        // initial control key hash prefix
        let pref1 = BasicPrefix::Ed25519(pub_key1);
        let nxt = nxt_commitment(
            SignatureThreshold::Simple(1),
            &vec![pref1],
            &SelfAddressing::Blake3_256,
        );

        // create a simple inception event
        let icp = KeyEvent::new(
            IdentifierPrefix::Basic(pref0.clone()),
            0,
            EventData::Icp(InceptionEvent {
                key_config: KeyConfig::new(
                    vec![pref0.clone()],
                    nxt.clone(),
                    Some(SignatureThreshold::Simple(1)),
                ),
                witness_config: InceptionWitnessConfig::default(),
                inception_configuration: vec![],
                data: vec![],
            }),
        );

        let icp_m = icp.to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;

        // serialised message
        let ser: Vec<_> = Versional::serialize(&icp_m)?;

        // sign
        let sig = priv_key0.sign_ed(&ser)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(sig), 0);

        assert!(pref0.verify(&ser, &attached_sig.signature)?);

        let signed_event = icp_m.sign(vec![attached_sig], None, None);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&ser, &signed_event.signatures)?);

        assert_eq!(s0.prefix, IdentifierPrefix::Basic(pref0.clone()));
        assert_eq!(s0.sn, 0);
        assert!(icp_m.compare_digest(&s0.last_event_digest)?);
        assert_eq!(s0.current.public_keys.len(), 1);
        assert_eq!(s0.current.public_keys[0], pref0);
        assert_eq!(s0.current.threshold, SignatureThreshold::Simple(1));
        assert_eq!(s0.current.next_keys_data, nxt);
        assert_eq!(s0.witness_config.witnesses, vec![]);
        assert_eq!(s0.witness_config.tally, SignatureThreshold::Simple(0));

        Ok(())
    }

    #[test]
    fn self_addressing_create() -> Result<(), Error> {
        // hi Ed!
        let kp0 = Keypair::generate(&mut OsRng);
        let kp1 = Keypair::generate(&mut OsRng);
        let kp2 = Keypair::generate(&mut OsRng);

        // get two ed25519 keypairs
        let pub_key0 = PublicKey::new(kp0.public.to_bytes().to_vec());
        let priv_key0 = PrivateKey::new(kp0.secret.to_bytes().to_vec());
        let (pub_key1, sig_key_1) = (
            PublicKey::new(kp1.public.to_bytes().to_vec()),
            PrivateKey::new(kp1.secret.to_bytes().to_vec()),
        );

        // hi X!
        // let x = XChaCha20Poly1305::new((&priv_key0.into_bytes()[..]).into());

        // get two X25519 keypairs
        let (enc_key_0, _enc_priv_0) = (PublicKey::new(kp2.public.to_bytes().to_vec()), sig_key_1);
        let (enc_key_1, _enc_priv_1) = (
            PublicKey::new(kp2.public.to_bytes().to_vec()),
            PrivateKey::new(kp2.secret.to_bytes().to_vec()),
        );

        // initial key set
        let sig_pref_0 = BasicPrefix::Ed25519(pub_key0);
        let enc_pref_0 = BasicPrefix::X25519(enc_key_0);

        // next key set
        let sig_pref_1 = BasicPrefix::Ed25519(pub_key1);
        let enc_pref_1 = BasicPrefix::X25519(enc_key_1);

        // next key set pre-commitment
        let nexter_pref = nxt_commitment(
            SignatureThreshold::default(),
            &[sig_pref_1, enc_pref_1],
            &SelfAddressing::Blake3_256,
        );

        let icp = InceptionEvent::new(
            KeyConfig::new(
                vec![sig_pref_0.clone(), enc_pref_0.clone()],
                nexter_pref.clone(),
                Some(SignatureThreshold::default()),
            ),
            None,
            None,
        )
        .incept_self_addressing(SelfAddressing::Blake3_256, SerializationFormats::JSON)?;

        // serialised
        let serialized: Vec<_> = Versional::serialize(&icp)?;

        // sign
        let sk = priv_key0;
        let sig = sk.sign_ed(&serialized)?;
        let attached_sig = AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(sig), 0);

        assert!(sig_pref_0.verify(&serialized, &attached_sig.signature)?);

        let signed_event = icp.sign(vec![attached_sig], None, None);

        let s_ = IdentifierState::default();

        let s0 = s_.apply(&signed_event)?;

        assert!(s0.current.verify(&serialized, &signed_event.signatures)?);

        assert_eq!(s0.prefix, icp.data.get_prefix());
        assert_eq!(s0.sn, 0);
        assert!(icp.compare_digest(&s0.last_event_digest)?);
        assert_eq!(s0.current.public_keys.len(), 2);
        assert_eq!(s0.current.public_keys[0], sig_pref_0);
        assert_eq!(s0.current.public_keys[1], enc_pref_0);
        assert_eq!(s0.current.threshold, SignatureThreshold::default());
        assert_eq!(s0.current.next_keys_data, nexter_pref);
        assert_eq!(s0.witness_config.witnesses, vec![]);
        assert_eq!(s0.witness_config.tally, SignatureThreshold::Simple(0));

        Ok(())
    }

    #[test]
    fn test_basic_establishment_sequence() -> Result<(), Error> {
        // Sequence should contain Inception Event.
        let no_inception_seq = vec![EventTypeTag::Rot, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(no_inception_seq).is_err());

        // Sequence can't start with Rotation Event.
        let rotation_first_seq = vec![EventTypeTag::Rot, EventTypeTag::Icp];
        assert!(test_mock_event_sequence(rotation_first_seq).is_err());

        // Sequence should contain exacly one Inception Event.
        let wrong_seq = vec![
            EventTypeTag::Icp,
            EventTypeTag::Rot,
            EventTypeTag::Rot,
            EventTypeTag::Icp,
        ];
        assert!(test_mock_event_sequence(wrong_seq).is_err());

        let ok_seq = vec![EventTypeTag::Icp, EventTypeTag::Rot, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        // Wrong delegated events sequence.
        let wrong_delegated_sequence =
            vec![EventTypeTag::Dip, EventTypeTag::Drt, EventTypeTag::Rot];
        assert!(test_mock_event_sequence(wrong_delegated_sequence).is_err());

        // Delegated events sequence.
        let delegated_sequence = vec![EventTypeTag::Dip, EventTypeTag::Drt, EventTypeTag::Ixn];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }

    #[test]
    fn test_basic_sequence() -> Result<(), Error> {
        let ok_seq = vec![
            EventTypeTag::Icp,
            EventTypeTag::Ixn,
            EventTypeTag::Ixn,
            EventTypeTag::Ixn,
            EventTypeTag::Rot,
            EventTypeTag::Ixn,
        ];
        assert!(test_mock_event_sequence(ok_seq).is_ok());

        let delegated_sequence = vec![
            EventTypeTag::Dip,
            EventTypeTag::Drt,
            EventTypeTag::Ixn,
            EventTypeTag::Drt,
        ];
        assert!(test_mock_event_sequence(delegated_sequence).is_ok());

        Ok(())
    }
}
