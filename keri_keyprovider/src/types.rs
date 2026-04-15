/// Cryptographic signature algorithms supported by key providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    Ed25519,
    EcdsaSecp256k1,
}

/// Raw public key data, algorithm-agnostic.
///
/// This is the provider-level representation of a public key, decoupled from
/// any KERI-specific types. Higher layers (keriox_core adapter) convert this
/// into the appropriate `BasicPrefix` / `PublicKey` types.
#[derive(Debug, Clone)]
pub struct PublicKeyData {
    pub algorithm: SignatureAlgorithm,
    pub bytes: Vec<u8>,
}

impl PublicKeyData {
    pub fn new(algorithm: SignatureAlgorithm, bytes: Vec<u8>) -> Self {
        Self { algorithm, bytes }
    }

    pub fn ed25519(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::Ed25519, bytes)
    }

    pub fn secp256k1(bytes: Vec<u8>) -> Self {
        Self::new(SignatureAlgorithm::EcdsaSecp256k1, bytes)
    }
}
