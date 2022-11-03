use core::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::error::Error;
use super::{verify, Prefix, SelfSigningPrefix};
use crate::event_parsing::codes::DerivationCode;
use crate::{
    event_parsing::{codes::basic::Basic as CesrBasic, parsing::from_text_to_bytes},
    keys::PublicKey,
};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum BasicPrefix {
    ECDSAsecp256k1NT(PublicKey),
    ECDSAsecp256k1(PublicKey),
    Ed25519NT(PublicKey),
    Ed25519(PublicKey),
    Ed448NT(PublicKey),
    Ed448(PublicKey),
    X25519(PublicKey),
    X448(PublicKey),
}

impl BasicPrefix {
    pub fn new(code: CesrBasic, public_key: PublicKey) -> Self {
        match code {
            CesrBasic::ECDSAsecp256k1NT => Self::ECDSAsecp256k1NT(public_key),
            CesrBasic::ECDSAsecp256k1 => Self::ECDSAsecp256k1(public_key),
            CesrBasic::Ed25519NT => Self::Ed25519NT(public_key),
            CesrBasic::Ed25519 => Self::Ed25519(public_key),
            CesrBasic::Ed448NT => Self::Ed448NT(public_key),
            CesrBasic::Ed448 => Self::Ed448(public_key),
            CesrBasic::X25519 => Self::X25519(public_key),
            CesrBasic::X448 => Self::X448(public_key),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &SelfSigningPrefix) -> Result<bool, Error> {
        verify(data, self, signature)
    }

    /// Non transferable means that the public key is always the current public key.
    /// Transferable means that the public key might have changed and
    /// you need to request KEL to obtain the newest one.
    pub fn is_transferable(&self) -> bool {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(_)
            | BasicPrefix::Ed25519NT(_)
            | BasicPrefix::Ed448NT(_) => false,
            _ => true,
        }
    }
}

impl FromStr for BasicPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = CesrBasic::from_str(s)?;

        if s.len() == code.prefix_b64_len() {
            let k_vec =
                from_text_to_bytes(&s[code.code_len()..].as_bytes())?[code.code_len()..].to_vec();
            Ok(Self::new(code.into(), PublicKey::new(k_vec)))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl Prefix for BasicPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(pk) => pk.key(),
            BasicPrefix::ECDSAsecp256k1(pk) => pk.key(),
            BasicPrefix::Ed25519NT(pk) => pk.key(),
            BasicPrefix::Ed25519(pk) => pk.key(),
            BasicPrefix::Ed448NT(pk) => pk.key(),
            BasicPrefix::Ed448(pk) => pk.key(),
            BasicPrefix::X25519(pk) => pk.key(),
            BasicPrefix::X448(pk) => pk.key(),
        }
    }
    fn derivation_code(&self) -> String {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(_) => CesrBasic::ECDSAsecp256k1NT,
            BasicPrefix::ECDSAsecp256k1(_) => CesrBasic::ECDSAsecp256k1,
            BasicPrefix::Ed25519NT(_) => CesrBasic::Ed25519NT,
            BasicPrefix::Ed25519(_) => CesrBasic::Ed25519,
            BasicPrefix::Ed448NT(_) => CesrBasic::Ed448NT,
            BasicPrefix::Ed448(_) => CesrBasic::Ed448,
            BasicPrefix::X25519(_) => CesrBasic::X25519,
            BasicPrefix::X448(_) => CesrBasic::X448,
        }
        .to_str()
    }
}

/// Serde compatible Serialize
impl Serialize for BasicPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for BasicPrefix {
    fn deserialize<D>(deserializer: D) -> Result<BasicPrefix, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        BasicPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[test]
fn serialize_deserialize() {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let kp = Keypair::generate(&mut OsRng);

    let bp = BasicPrefix::Ed25519(PublicKey::new(kp.public.to_bytes().to_vec()));

    let serialized = serde_json::to_string(&bp);
    assert!(serialized.is_ok());

    let deserialized = serde_json::from_str(&serialized.unwrap());

    assert!(deserialized.is_ok());
    assert_eq!(bp, deserialized.unwrap());
}

#[test]
fn to_from_string() {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    use crate::keys::PrivateKey;

    let kp = Keypair::generate(&mut OsRng);

    let signer = PrivateKey::new(kp.secret.to_bytes().to_vec());

    let message = b"hello there";
    let sig = SelfSigningPrefix::new(
        crate::derivation::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign_ed(message).unwrap(),
    );

    let bp = BasicPrefix::Ed25519(PublicKey::new(kp.public.to_bytes().to_vec()));

    assert!(bp.verify(message, &sig).unwrap());

    let string = bp.to_str();

    let from_str = BasicPrefix::from_str(&string);

    assert!(from_str.is_ok());
    let deser = from_str.unwrap();
    assert_eq!(bp, deser);

    assert!(deser.verify(message, &sig).unwrap());
}
