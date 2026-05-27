use core::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{error::Error, verify, SelfSigningPrefix};
use crate::{event::sections::key_config::SignatureError, keys::PublicKey};
use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::{
        codes::{basic::Basic as CesrBasic, PrimitiveCode},
        CesrPrimitive,
    },
};

#[derive(Clone, Eq, PartialEq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum BasicPrefix {
    ECDSAsecp256k1NT(PublicKey),
    ECDSAsecp256k1(PublicKey),
    Ed25519NT(PublicKey),
    Ed25519(PublicKey),
    Ed448NT(PublicKey),
    Ed448(PublicKey),
    X25519(PublicKey),
    X448(PublicKey),
    ECDSA256r1NT(PublicKey),
    ECDSA256r1(PublicKey),
}

impl fmt::Debug for BasicPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.to_str())
    }
}

impl BasicPrefix {
    pub fn new(code: CesrBasic, public_key: PublicKey) -> Self {
        match code {
            CesrBasic::ECDSAsecp256k1Nontrans => Self::ECDSAsecp256k1NT(public_key),
            CesrBasic::ECDSAsecp256k1 => Self::ECDSAsecp256k1(public_key),
            CesrBasic::Ed25519Nontrans => Self::Ed25519NT(public_key),
            CesrBasic::Ed25519 => Self::Ed25519(public_key),
            CesrBasic::Ed448Nontrans => Self::Ed448NT(public_key),
            CesrBasic::Ed448 => Self::Ed448(public_key),
            CesrBasic::X25519 => Self::X25519(public_key),
            CesrBasic::X448 => Self::X448(public_key),
            CesrBasic::ECDSA256r1Nontrans => Self::ECDSA256r1NT(public_key),
            CesrBasic::ECDSA256r1 => Self::ECDSA256r1(public_key),
        }
    }

    pub fn verify(
        &self,
        data: &[u8],
        signature: &SelfSigningPrefix,
    ) -> Result<bool, SignatureError> {
        verify(data, self, signature)
    }

    /// The CESR [`SelfSigning`](cesrox::primitives::codes::self_signing::SelfSigning)
    /// code matching this key's algorithm.
    ///
    /// Returns `None` for variants that cannot produce signatures (X25519,
    /// X448 — these are Diffie-Hellman key-agreement keys, not signing
    /// keys). Use this to wrap raw signature bytes in the right
    /// `SelfSigningPrefix` variant when you only hold a `BasicPrefix`.
    pub fn signing_code(
        &self,
    ) -> Option<cesrox::primitives::codes::self_signing::SelfSigning> {
        use cesrox::primitives::codes::self_signing::SelfSigning;
        Some(match self {
            BasicPrefix::Ed25519(_) | BasicPrefix::Ed25519NT(_) => SelfSigning::Ed25519Sha512,
            BasicPrefix::ECDSAsecp256k1(_) | BasicPrefix::ECDSAsecp256k1NT(_) => {
                SelfSigning::ECDSAsecp256k1Sha256
            }
            BasicPrefix::Ed448(_) | BasicPrefix::Ed448NT(_) => SelfSigning::Ed448,
            BasicPrefix::ECDSA256r1(_) | BasicPrefix::ECDSA256r1NT(_) => {
                SelfSigning::ECDSA256r1Sha256
            }
            BasicPrefix::X25519(_) | BasicPrefix::X448(_) => return None,
        })
    }

    /// Non transferable means that the public key is always the current public key.
    /// Transferable means that the public key might have changed and
    /// you need to request KEL to obtain the newest one.
    pub fn is_transferable(&self) -> bool {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(_)
            | BasicPrefix::Ed25519NT(_)
            | BasicPrefix::Ed448NT(_)
            | BasicPrefix::ECDSA256r1NT(_) => false,
            _ => true,
        }
    }

    pub fn get_code(&self) -> CesrBasic {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(_) => CesrBasic::ECDSAsecp256k1Nontrans,
            BasicPrefix::ECDSAsecp256k1(_) => CesrBasic::ECDSAsecp256k1,
            BasicPrefix::Ed25519NT(_) => CesrBasic::Ed25519Nontrans,
            BasicPrefix::Ed25519(_) => CesrBasic::Ed25519,
            BasicPrefix::Ed448NT(_) => CesrBasic::Ed448Nontrans,
            BasicPrefix::Ed448(_) => CesrBasic::Ed448,
            BasicPrefix::X25519(_) => CesrBasic::X25519,
            BasicPrefix::X448(_) => CesrBasic::X448,
            BasicPrefix::ECDSA256r1NT(_) => CesrBasic::ECDSA256r1Nontrans,
            BasicPrefix::ECDSA256r1(_) => CesrBasic::ECDSA256r1,
        }
    }
}

impl FromStr for BasicPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = CesrBasic::from_str(s)?;

        if s.len() == code.full_size() {
            // Match cesrox's parse_primitive: strip only the lead-padding bytes
            // implicitly added by from_text_to_bytes (which only happens when the
            // code length is not a multiple of 4). Stripping the full code_size
            // would silently truncate the value for 4-char codes (1AAA/1AAB
            // secp256k1, 1AAC/1AAD Ed448, 1AAI/1AAJ P-256).
            let k_vec = from_text_to_bytes(&s[code.code_size()..])?[code.code_size() % 4..]
                .to_vec();
            Ok(Self::new(code, PublicKey::new(k_vec)))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl CesrPrimitive for BasicPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            BasicPrefix::ECDSAsecp256k1NT(pk)
            | BasicPrefix::ECDSAsecp256k1(pk)
            | BasicPrefix::Ed25519NT(pk)
            | BasicPrefix::Ed25519(pk)
            | BasicPrefix::Ed448NT(pk)
            | BasicPrefix::Ed448(pk)
            | BasicPrefix::X25519(pk)
            | BasicPrefix::X448(pk)
            | BasicPrefix::ECDSA256r1NT(pk)
            | BasicPrefix::ECDSA256r1(pk) => pk.key(),
        }
    }
    fn derivation_code(&self) -> PrimitiveCode {
        PrimitiveCode::Basic(self.get_code())
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
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    let kp = SigningKey::generate(&mut OsRng);

    let bp = BasicPrefix::Ed25519(PublicKey::new(kp.verifying_key().to_bytes().to_vec()));

    let serialized = serde_json::to_string(&bp);
    assert!(serialized.is_ok());

    let deserialized = serde_json::from_str::<BasicPrefix>(&serialized.unwrap());

    assert!(deserialized.is_ok());
    assert_eq!(bp, deserialized.unwrap());
}

#[test]
fn to_from_string() {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use crate::keys::PrivateKey;

    let kp = SigningKey::generate(&mut OsRng);

    let signer = PrivateKey::new(kp.to_bytes().to_vec());

    let message = b"hello there";
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign_ed(message).unwrap());

    let bp = BasicPrefix::Ed25519(PublicKey::new(kp.verifying_key().to_bytes().to_vec()));

    assert!(bp.verify(message, &sig).unwrap());

    let string = bp.to_str();

    let from_str = BasicPrefix::from_str(&string);

    assert!(from_str.is_ok());
    let deser = from_str.unwrap();
    assert_eq!(bp, deser);

    assert!(deser.verify(message, &sig).unwrap());
}
