use std::str::FromStr;

use super::error::Error;
use super::CesrPrimitive;
use crate::keys::{KeysError, PrivateKey, PublicKey};
use cesrox::{
    conversion::from_text_to_bytes,
    derivation_code::DerivationCode,
    primitives::codes::{seed::SeedCode, PrimitiveCode},
};
use k256::ecdsa::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(Debug, PartialEq, Clone)]
pub enum SeedPrefix {
    RandomSeed128(Vec<u8>),
    RandomSeed256Ed25519(Vec<u8>),
    RandomSeed256ECDSAsecp256k1(Vec<u8>),
    RandomSeed448(Vec<u8>),
}

impl SeedPrefix {
    pub fn new(code: SeedCode, value: Vec<u8>) -> Self {
        match code {
            SeedCode::RandomSeed128 => Self::RandomSeed128(value),
            SeedCode::RandomSeed256Ed25519 => Self::RandomSeed256Ed25519(value),
            SeedCode::RandomSeed256ECDSAsecp256k1 => Self::RandomSeed256ECDSAsecp256k1(value),
            SeedCode::RandomSeed448 => Self::RandomSeed448(value),
        }
    }

    pub fn derive_key_pair(&self) -> Result<(PublicKey, PrivateKey), Error> {
        match self {
            Self::RandomSeed256Ed25519(seed) => {
                let key: &[u8; 32] = match seed.as_slice().try_into() {
                    Ok(arr) => arr,
                    Err(_) => return Err(KeysError::Ed25519DalekKeyError.into()),
                };
                let secret = ed25519_dalek::SigningKey::from_bytes(key);
                let vk = PublicKey::new(secret.verifying_key().to_bytes().to_vec());
                let sk = PrivateKey::new(secret.to_bytes().to_vec());
                Ok((vk, sk))
            }
            Self::RandomSeed256ECDSAsecp256k1(seed) => {
                let sk = SigningKey::from_bytes(seed).map_err(|_e| KeysError::EcdsaError)?;
                Ok((
                    PublicKey::new(VerifyingKey::from(&sk).to_bytes().to_vec()),
                    PrivateKey::new(sk.to_bytes().to_vec()),
                ))
            }
            _ => Err(Error::WrongSeedTypeError),
        }
    }
}

impl FromStr for SeedPrefix {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = SeedCode::from_str(s)?;

        if s.len() == code.full_size() {
            let k_vec =
                from_text_to_bytes(s[code.code_size()..].as_bytes())?[code.code_size()..].to_vec();
            Ok(Self::new(code, k_vec))
        } else {
            Err(Error::IncorrectLengthError(s.into()))
        }
    }
}

impl CesrPrimitive for SeedPrefix {
    fn derivative(&self) -> Vec<u8> {
        match self {
            Self::RandomSeed256Ed25519(seed) => seed.to_owned(),
            Self::RandomSeed256ECDSAsecp256k1(seed) => seed.to_owned(),
            Self::RandomSeed448(seed) => seed.to_owned(),
            Self::RandomSeed128(seed) => seed.to_owned(),
        }
    }
    fn derivation_code(&self) -> PrimitiveCode {
        match self {
            Self::RandomSeed256Ed25519(_) => PrimitiveCode::Seed(SeedCode::RandomSeed256Ed25519),
            Self::RandomSeed256ECDSAsecp256k1(_) => {
                PrimitiveCode::Seed(SeedCode::RandomSeed256ECDSAsecp256k1)
            }
            Self::RandomSeed448(_) => PrimitiveCode::Seed(SeedCode::RandomSeed448),
            Self::RandomSeed128(_) => PrimitiveCode::Seed(SeedCode::RandomSeed448),
        }
    }
}

/// Serde compatible Serialize
impl Serialize for SeedPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_str())
    }
}

/// Serde compatible Deserialize
impl<'de> Deserialize<'de> for SeedPrefix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;

        SeedPrefix::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[test]
fn test_derive_keypair() -> Result<(), Error> {
    use crate::prefix::basic::BasicPrefix;
    use base64::URL_SAFE;

    // taken from KERIPY: tests/core/test_eventing.py#1512
    let seeds = vec![
        "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH",
        "AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0",
        "AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG",
        "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP",
        "ANfkMQ5LKPfjEdQPK2c_zWsOn4GgLWsnWvIa25EVVbtR",
        "ACrmDHtPQjnM8H9pyKA-QBNdfZ-xixTlRZTS8WXCrrMH",
        "AMRXyU3ErhBNdRSDX1zKlrbZGRp1GfCmkRIa58gF07I8",
        "AC6vsNVCpHa6acGcxk7c-D1mBHlptPrAx8zr-bKvesSW",
    ];

    let expected_pubkeys = vec![
        "SuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA=",
        "VcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI=",
        "T1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8=",
        "KPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ=",
        "1kcBE7h0ImWW6_Sp7MQxGYSshZZz6XM7OiUE5DXm0dU=",
        "4JDgo3WNSUpt-NG14Ni31_GCmrU0r38yo7kgDuyGkQM=",
        "VjWcaNX2gCkHOjk6rkmqPBCxkRCqwIJ-3OjdYmMwxf4=",
        "T1nEDepd6CSAMCE7NY_jlLdG6_mKUlKS_mW-2HJY1hg=",
    ];
    let expected_basic_prefix = vec![
        "DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q",
        "DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS",
        "DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f",
        "DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE",
        "DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV",
        "DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED",
        "DFY1nGjV9oApBzo5Oq5JqjwQsZEQqsCCftzo3WJjMMX-",
        "DE9ZxA3qXegkgDAhOzWP45S3Ruv5ilJSkv5lvthyWNYY",
    ];

    for (seed_str, (expected_pk, expected_bp)) in seeds
        .iter()
        .zip(expected_pubkeys.iter().zip(expected_basic_prefix.iter()))
    {
        let seed: SeedPrefix = seed_str.parse()?;
        let (pub_key, _priv_key) = seed.derive_key_pair()?;
        let b64_pubkey = base64::encode_config(pub_key.key(), URL_SAFE);
        let bp = BasicPrefix::Ed25519(pub_key);
        assert_eq!(&bp.to_str(), expected_bp);
        assert_eq!(&b64_pubkey, expected_pk);
    }

    Ok(())
}

#[test]
fn test_derive_from_seed() {
    use cesrox::primitives::codes::seed::SeedCode;
    use rand::rngs::OsRng;
    let ed_keypair = ed25519_dalek::SigningKey::generate(&mut OsRng);

    let sp = SeedPrefix::new(
        SeedCode::RandomSeed256Ed25519,
        ed_keypair.as_bytes().to_vec(),
    );

    let (derived_pub_key, derived_priv_key) = sp.derive_key_pair().unwrap();
    assert_eq!(derived_pub_key.key(), ed_keypair.verifying_key().to_bytes());
    assert_eq!(derived_priv_key.key(), ed_keypair.to_bytes());
}
