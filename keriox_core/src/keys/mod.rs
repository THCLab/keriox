use ed25519_dalek::Signer;
use k256::ecdsa::{signature::Signer as EcdsaSigner, Signature as EcdsaSignature, SigningKey};
use k256::ecdsa::{signature::Verifier as EcdsaVerifier, VerifyingKey};
use p256::ecdsa::{
    signature::{Signer as P256Signer, Verifier as P256Verifier},
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
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
            // `verify` accepts small-order keys and R values, so for a
            // small-order key anyone can produce a signature valid for any
            // message. `verify_strict` rejects them, matching libsodium.
            match key.verify_strict(msg, &sig) {
                Ok(()) => true,
                Err(_) => false,
            }
        } else {
            false
        }
    }

    /// Whether the key is a canonically encoded Ed25519 point outside the
    /// small-order subgroup, the same criteria libsodium applies to public
    /// keys. Signatures for small-order keys can be produced without any
    /// secret, so such keys must never be accepted into key state.
    pub fn is_valid_ed(&self) -> bool {
        let Ok(bytes) = <[u8; 32]>::try_from(self.public_key.as_slice()) else {
            return false;
        };
        match ed25519_dalek::VerifyingKey::from_bytes(&bytes) {
            Ok(key) => !key.is_weak() && key.to_edwards().compress().to_bytes() == bytes,
            Err(_) => false,
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

    pub fn verify_p256(&self, msg: &[u8], sig: &[u8]) -> bool {
        match P256VerifyingKey::from_sec1_bytes(&self.key()) {
            Ok(k) => match P256Signature::try_from(sig) {
                Ok(sig) => P256Verifier::verify(&k, msg, &sig).is_ok(),
                Err(_) => false,
            },
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

    pub fn sign_p256(&self, msg: &[u8]) -> Result<Vec<u8>, KeysError> {
        let sk =
            P256SigningKey::from_bytes(&self.key).map_err(|_| KeysError::EcdsaError)?;
        let sig: P256Signature = P256Signer::sign(&sk, msg);
        Ok(sig.as_ref().to_vec())
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
fn p256_sign_verify_roundtrip() {
    use rand::rngs::OsRng;
    let sk = P256SigningKey::random(&mut OsRng);
    let vk = P256VerifyingKey::from(&sk);
    let pub_key = PublicKey::new(vk.to_encoded_point(true).as_bytes().to_vec());
    let priv_key = PrivateKey::new(sk.to_bytes().to_vec());

    let msg = b"native-curve mobile sign";
    let sig = priv_key.sign_p256(msg).unwrap();
    assert_eq!(sig.len(), 64, "P-256 sig must be raw 64-byte r||s");
    assert!(pub_key.verify_p256(msg, &sig));
    assert!(!pub_key.verify_p256(b"tampered", &sig));
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

/// Small-order points of edwards25519 (canonical encodings of the 8-torsion
/// subgroup) followed by non-canonical encodings of small-order points.
#[cfg(test)]
const SMALL_ORDER_KEYS: [&str; 10] = [
    // identity
    "0100000000000000000000000000000000000000000000000000000000000000",
    // order 2
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // order 4
    "0000000000000000000000000000000000000000000000000000000000000000",
    "0000000000000000000000000000000000000000000000000000000000000080",
    // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
    // identity encoded as y = p + 1
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // identity encoded as y = 1 with the sign bit set
    "0100000000000000000000000000000000000000000000000000000000000080",
];

#[test]
fn verify_ed_rejects_signature_for_small_order_key() {
    use sodiumoxide::crypto::sign;

    // R = identity, S = 0 satisfies the permissive verification equation
    // [S]B = R + [k]A for every message when A is the identity point.
    let mut universal_sig = [0u8; 64];
    universal_sig[0] = 1;

    for key in [SMALL_ORDER_KEYS[0], SMALL_ORDER_KEYS[8]] {
        let key = hex::decode(key).unwrap();
        let sodium_pk = sign::ed25519::PublicKey::from_slice(&key).unwrap();
        let sodium_sig = sign::ed25519::Signature::from_bytes(&universal_sig).unwrap();
        for msg in [&b"first message"[..], &b"second message"[..]] {
            // The forgery is real: dalek's permissive check accepts it.
            let vk = ed25519_dalek::VerifyingKey::from_bytes(key.as_slice().try_into().unwrap())
                .unwrap();
            let sig = ed25519_dalek::Signature::from_bytes(&universal_sig);
            assert!(ed25519_dalek::Verifier::verify(&vk, msg, &sig).is_ok());

            assert!(!PublicKey::new(key.clone()).verify_ed(msg, &universal_sig));
            assert!(!sign::verify_detached(&sodium_sig, msg, &sodium_pk));
        }
    }
}

#[test]
fn verify_ed_rejects_small_order_r() {
    use rand::rngs::OsRng;

    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    let pk = PublicKey::new(sk.verifying_key().to_bytes().to_vec());
    let msg = b"message";
    assert!(pk.verify_ed(msg, &sk.sign(msg).to_bytes()));

    for r in SMALL_ORDER_KEYS {
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&hex::decode(r).unwrap());
        assert!(!pk.verify_ed(msg, &sig));
    }
}

#[test]
fn is_valid_ed_rejects_weak_and_non_canonical_keys() {
    use rand::rngs::OsRng;

    let sk = ed25519_dalek::SigningKey::generate(&mut OsRng);
    assert!(PublicKey::new(sk.verifying_key().to_bytes().to_vec()).is_valid_ed());

    for key in SMALL_ORDER_KEYS {
        assert!(
            !PublicKey::new(hex::decode(key).unwrap()).is_valid_ed(),
            "{key}"
        );
    }

    // y = p + 3 decodes to a point of full order, but the encoding is not
    // canonical; libsodium rejects such keys.
    let non_canonical =
        hex::decode("f0ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f").unwrap();
    assert!(
        ed25519_dalek::VerifyingKey::from_bytes(non_canonical.as_slice().try_into().unwrap())
            .is_ok_and(|key| !key.is_weak())
    );
    assert!(!PublicKey::new(non_canonical).is_valid_ed());

    // Not a point on the curve (y = 2) and wrong length.
    let mut off_curve = [0u8; 32];
    off_curve[0] = 2;
    assert!(!PublicKey::new(off_curve.to_vec()).is_valid_ed());
    assert!(!PublicKey::new(vec![1u8; 31]).is_valid_ed());
}
