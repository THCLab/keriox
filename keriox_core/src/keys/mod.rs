use ed25519_dalek::{Signer, Verifier};
use k256::ecdsa::{signature::Signer as EcdsaSigner, Signature as EcdsaSignature, SigningKey};
use k256::ecdsa::{signature::Verifier as EcdsaVerifier, VerifyingKey};
use serde_derive::{Deserialize, Serialize};
use zeroize::Zeroize;

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum KeysError {
    #[error("ED25519Dalek key error")]
    Ed25519DalekKeyError,
    #[error("ED25519Dalek signature error")]
    Ed25519DalekSignatureError,
    #[error("ECDSA signature error")]
    EcdsaError,
}

impl From<ed25519_dalek::SignatureError> for KeysError {
    fn from(_: ed25519_dalek::SignatureError) -> Self {
        KeysError::Ed25519DalekSignatureError
    }
}

#[derive(
    Debug, Clone, PartialEq, Hash, Eq, Default, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub struct PublicKey {
    pub public_key: Vec<u8>,
}

impl PublicKey {
    pub fn new(key: Vec<u8>) -> Self {
        PublicKey {
            public_key: key.to_vec(),
        }
    }

    pub fn key(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    pub fn verify_ed(&self, msg: &[u8], sig: &[u8]) -> bool {
        let binding = self.key();
        let key: &[u8; 32] = match binding.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => panic!("Vector does not have exactly 32 elements"),
        };
        if let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(key) {
            use arrayref::array_ref;
            if sig.len() != 64 {
                return false;
            }
            let sig = ed25519_dalek::Signature::from(array_ref!(sig, 0, 64).to_owned());
            match key.verify(msg, &sig) {
                Ok(()) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    pub fn verify_ecdsa(&self, msg: &[u8], sig: &[u8]) -> bool {
        match VerifyingKey::from_sec1_bytes(&self.key()) {
            Ok(k) => {
                use k256::ecdsa::Signature;
                if let Ok(sig) = Signature::try_from(sig) {
                    match k.verify(msg, &sig) {
                        Ok(()) => true,
                        Err(_) => false,
                    }
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PrivateKey {
    key: Vec<u8>,
}

impl PrivateKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn sign_ecdsa(&self, msg: &[u8]) -> Result<Vec<u8>, KeysError> {
        let sig: EcdsaSignature = EcdsaSigner::sign(
            &SigningKey::from_bytes(&self.key).map_err(|_e| KeysError::Ed25519DalekKeyError)?,
            msg,
        );
        Ok(sig.as_ref().to_vec())
    }

    pub fn sign_ed(&self, msg: &[u8]) -> Result<Vec<u8>, KeysError> {
        let sk = ed25519_dalek::SigningKey::from_bytes(arrayref::array_ref![self.key, 0, 32]);

        Ok(sk.sign(msg).to_vec())
    }

    pub fn key(&self) -> Vec<u8> {
        self.key.clone()
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        self.key.zeroize()
    }
}

#[test]
fn libsodium_to_ed25519_dalek_compat() {
    use ed25519_dalek::Signature;
    use rand::rngs::OsRng;

    let kp = ed25519_dalek::SigningKey::generate(&mut OsRng);

    let msg = b"are libsodium and dalek compatible?";

    let dalek_sig = kp.sign(msg);

    use sodiumoxide::crypto::sign;

    let sodium_pk = sign::ed25519::PublicKey::from_slice(&kp.verifying_key().to_bytes());
    assert!(sodium_pk.is_some());
    let sodium_pk = sodium_pk.unwrap();
    let mut sodium_sk_concat = kp.to_bytes().to_vec();
    sodium_sk_concat.append(&mut kp.verifying_key().to_bytes().to_vec().clone());
    let sodium_sk = sign::ed25519::SecretKey::from_slice(&sodium_sk_concat);
    assert!(sodium_sk.is_some());
    let sodium_sk = sodium_sk.unwrap();

    let sodium_sig = sign::sign(msg, &sodium_sk);

    assert!(sign::verify_detached(
        &sign::ed25519::Signature::from_bytes(&dalek_sig.to_bytes()).unwrap(),
        msg,
        &sodium_pk
    ));

    assert!(kp
        .verify(
            msg,
            &Signature::from_bytes(&arrayref::array_ref!(sodium_sig, 0, 64).to_owned())
        )
        .is_ok());
}
