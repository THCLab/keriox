use crate::{
    error::Error,
    keys::{PrivateKey, PublicKey},
    prefix::SeedPrefix,
};
use rand::rngs::OsRng;

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
        self.signer.sign(msg)
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
}

impl Signer {
    /// Creates a new Signer with a random key.
    pub fn new() -> Self {
        let ed = ed25519_dalek::Keypair::generate(&mut OsRng);
        let pub_key = PublicKey::new(ed.public.to_bytes().to_vec());
        let priv_key = PrivateKey::new(ed.secret.to_bytes().to_vec());

        Signer { pub_key, priv_key }
    }

    /// Creates a new Signer with the given ED25519_dalek private key.
    pub fn new_with_key(priv_key: &[u8]) -> Result<Self, ed25519_dalek::SignatureError> {
        let priv_key = ed25519_dalek::SecretKey::from_bytes(priv_key)?;
        let pub_key = ed25519_dalek::PublicKey::from(&priv_key);

        Ok(Signer {
            priv_key: PrivateKey::new(priv_key.as_bytes().to_vec()),
            pub_key: PublicKey::new(pub_key.as_bytes().to_vec()),
        })
    }

    pub fn new_with_seed(seed: &SeedPrefix) -> Result<Self, Error> {
        let (public_key, private_key) = seed.derive_key_pair()?;

        Ok(Signer {
            priv_key: private_key,
            pub_key: public_key,
        })
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.priv_key.sign_ed(msg.as_ref())
    }

    pub fn public_key(&self) -> PublicKey {
        self.pub_key.clone()
    }
}

impl Default for Signer {
    fn default() -> Self {
        Self::new()
    }
}

fn generate_key_pair() -> Result<(PublicKey, PrivateKey), Error> {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    Ok((vk, sk))
}

/// Helper function to generate keypairs that can be used for signing in tests.
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
        Signer::new_with_key(&sk.key()).unwrap()
    })
    .collect::<Vec<_>>()
}
