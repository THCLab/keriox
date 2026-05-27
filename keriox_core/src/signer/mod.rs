use cesrox::primitives::codes::self_signing::SelfSigning;
use rand::rngs::OsRng;

use crate::{
    error::Error,
    keys::{KeysError, PrivateKey, PublicKey},
    prefix::{BasicPrefix, SeedPrefix},
};

/// Which cryptographic algorithm a [`Signer`] uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignerAlgorithm {
    Ed25519,
    EcdsaSecp256k1,
    EcdsaSecp256r1,
}

pub trait KeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> PublicKey;
    fn next_public_key(&self) -> PublicKey;
    fn rotate(&mut self) -> Result<(), Error>;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: PrivateKey,
    pub next_pub_key: PublicKey,
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.signer.sign(msg)?)
    }

    fn public_key(&self) -> PublicKey {
        self.signer.pub_key.clone()
    }

    fn next_public_key(&self) -> PublicKey {
        self.next_pub_key.clone()
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let (next_pub_key, next_priv_key) = generate_key_pair()?;

        let new_signer = Signer {
            priv_key: self.next_priv_key.clone(),
            pub_key: self.next_pub_key.clone(),
            algorithm: self.signer.algorithm,
        };
        self.signer = new_signer;
        self.next_priv_key = next_priv_key;
        self.next_pub_key = next_pub_key;

        Ok(())
    }
}
impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let signer = Signer::new();
        let (next_pub_key, next_priv_key) = generate_key_pair()?;
        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
        })
    }
}

pub struct Signer {
    priv_key: PrivateKey,
    pub_key: PublicKey,
    algorithm: SignerAlgorithm,
}

impl Signer {
    /// Creates a new Signer with a random Ed25519 key.
    pub fn new() -> Self {
        let ed = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let pub_key = PublicKey::new(ed.verifying_key().to_bytes().to_vec());
        let priv_key = PrivateKey::new(ed.to_bytes().to_vec());

        Signer {
            pub_key,
            priv_key,
            algorithm: SignerAlgorithm::Ed25519,
        }
    }

    /// Creates a new Signer with the given ED25519_dalek private key.
    pub fn new_with_key(priv_key: &[u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let priv_key = ed25519_dalek::SigningKey::from_bytes(priv_key);
        let pub_key = ed25519_dalek::VerifyingKey::from(&priv_key);

        Ok(Signer {
            priv_key: PrivateKey::new(priv_key.as_bytes().to_vec()),
            pub_key: PublicKey::new(pub_key.as_bytes().to_vec()),
            algorithm: SignerAlgorithm::Ed25519,
        })
    }

    /// Construct a [`Signer`] from any supported [`SeedPrefix`] variant.
    ///
    /// The algorithm is inferred from the seed variant so subsequent calls to
    /// [`Signer::sign`], [`Signer::signing_code`], and [`Signer::basic_prefix`]
    /// dispatch to the right primitive without further configuration.
    pub fn new_with_seed(seed: &SeedPrefix) -> Result<Self, Error> {
        let (public_key, private_key) = seed.derive_key_pair()?;
        let algorithm = match seed {
            SeedPrefix::RandomSeed256Ed25519(_) => SignerAlgorithm::Ed25519,
            SeedPrefix::RandomSeed256ECDSAsecp256k1(_) => SignerAlgorithm::EcdsaSecp256k1,
            SeedPrefix::RandomSeed256ECDSA256r1(_) => SignerAlgorithm::EcdsaSecp256r1,
            SeedPrefix::RandomSeed448(_) => {
                return Err(Error::SemanticError(
                    "Ed448 signing seeds are not yet supported by Signer".into(),
                ));
            }
        };

        Ok(Signer {
            priv_key: private_key,
            pub_key: public_key,
            algorithm,
        })
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>, KeysError> {
        match self.algorithm {
            SignerAlgorithm::Ed25519 => self.priv_key.sign_ed(msg.as_ref()),
            SignerAlgorithm::EcdsaSecp256k1 => self.priv_key.sign_ecdsa(msg.as_ref()),
            SignerAlgorithm::EcdsaSecp256r1 => self.priv_key.sign_p256(msg.as_ref()),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }

    /// The [`SelfSigning`] CESR code matching this signer's algorithm.
    ///
    /// Callers wrapping raw signature bytes in a `SelfSigningPrefix` should
    /// use this code instead of hardcoding `Ed25519Sha512`.
    pub fn signing_code(&self) -> SelfSigning {
        match self.algorithm {
            SignerAlgorithm::Ed25519 => SelfSigning::Ed25519Sha512,
            SignerAlgorithm::EcdsaSecp256k1 => SelfSigning::ECDSAsecp256k1Sha256,
            SignerAlgorithm::EcdsaSecp256r1 => SelfSigning::ECDSA256r1Sha256,
        }
    }

    /// The signer's algorithm.
    pub fn algorithm(&self) -> SignerAlgorithm {
        self.algorithm
    }

    /// Wrap this signer's public key in the [`BasicPrefix`] variant matching
    /// its algorithm.
    ///
    /// `transferable = true` returns the rotation-capable variant
    /// (Ed25519 / ECDSAsecp256k1 / ECDSA256r1); `false` returns the
    /// non-transferable variant.
    pub fn basic_prefix(&self, transferable: bool) -> BasicPrefix {
        match (self.algorithm, transferable) {
            (SignerAlgorithm::Ed25519, true) => BasicPrefix::Ed25519(self.pub_key.clone()),
            (SignerAlgorithm::Ed25519, false) => BasicPrefix::Ed25519NT(self.pub_key.clone()),
            (SignerAlgorithm::EcdsaSecp256k1, true) => {
                BasicPrefix::ECDSAsecp256k1(self.pub_key.clone())
            }
            (SignerAlgorithm::EcdsaSecp256k1, false) => {
                BasicPrefix::ECDSAsecp256k1NT(self.pub_key.clone())
            }
            (SignerAlgorithm::EcdsaSecp256r1, true) => {
                BasicPrefix::ECDSA256r1(self.pub_key.clone())
            }
            (SignerAlgorithm::EcdsaSecp256r1, false) => {
                BasicPrefix::ECDSA256r1NT(self.pub_key.clone())
            }
        }
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_key_pair() -> Result<(PublicKey, PrivateKey), Error> {
    let kp = ed25519_dalek::SigningKey::generate(&mut OsRng {});
    let (vk, sk) = (kp.verifying_key(), kp);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    Ok((vk, sk))
}

/// Helper function to generate keypairs that can be used for signing in tests.
#[cfg(test)]
pub(crate) fn setup_signers() -> Vec<Signer> {
    vec![
        "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH",
        "AOs8-zNPPh0EhavdrCfCiTk9nGeO8e6VxUCzwdKXJAd0",
        "AHMBU5PsIJN2U9m7j0SGyvs8YD8fkym2noELzxIrzfdG",
        "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP",
        "ANfkMQ5LKPfjEdQPK2c_zWsOn4GgLWsnWvIa25EVVbtR",
        "ACrmDHtPQjnM8H9pyKA-QBNdfZ-xixTlRZTS8WXCrrMH",
        "AMRXyU3ErhBNdRSDX1zKlrbZGRp1GfCmkRIa58gF07I8",
        "AC6vsNVCpHa6acGcxk7c-D1mBHlptPrAx8zr-bKvesSW",
        "AAD8sznuHWMw7cl6eZJQLm8PGBKvCjQzDH1Ui9ygH0Uo",
        "ANqQNn_9UjfayUJNdQobmixrH9qJF1cltKDwDMVkiLg8",
        "A1t7ix1GuZIP48r6ljsoo8jPsB9dEnnWNfhy2XNl1r-c",
        "AhzCysVY12fWXfkH1QkAOCY6oYbVwXOaUjf7YPtIfC8U",
        "A4HrsYq9XfxYK76ffoceNzj9n8tBkXrWNBIXUNdoe5ME",
        "AhpAiPtDqDcEeU_eXlJ8Bk3kJE0g0jdezyXZdBKfXslU",
        "AzN9fKZAZEIn9jMN2fZ2B35MNMQJPAZrNrJQRMi_S_8g",
        "AkNrzLqnqRx9WCpJAwTAOE5oNaDlOgOYiuM9bL4HM9R0",
        "ALjR-EE3jUF2yXW7Tq7WJSh3OFc6-BNxXJ9jGdfwA6Bs",
        "AvpsEhige2ssBrMxskK2xXpeKfed4cvcZCIdRh7fhgiI",
    ]
    .iter()
    .map(|key| {
        let (_pk, sk) = key
            .parse::<SeedPrefix>()
            .unwrap()
            .derive_key_pair()
            .unwrap();
        Signer::new_with_key(&sk.key().try_into().unwrap()).unwrap()
    })
    .collect::<Vec<_>>()
}
