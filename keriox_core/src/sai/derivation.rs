use super::{digest, SelfAddressingPrefix};

/// Self Addressing Derivations
///
/// Self-addressing is a digest/hash of some inception data (2.3.2)
///   Delegated Self-addressing uses the Dip event data for the inception data (2.3.4)
#[derive(Debug, PartialEq, Clone, Hash, Eq)]
pub enum SelfAddressing {
    Blake3_256,
    Blake2B256(Vec<u8>),
    Blake2S256(Vec<u8>),
    SHA3_256,
    SHA2_256,
    Blake3_512,
    SHA3_512,
    Blake2B512,
    SHA2_512,
}

impl SelfAddressing {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Blake3_256 => digest::blake3_256_digest(data),
            Self::Blake2B256(key) => digest::blake2b_256_digest(data, key),
            Self::Blake2S256(key) => digest::blake2s_256_digest(data, key),
            Self::SHA3_256 => digest::sha3_256_digest(data),
            Self::SHA2_256 => digest::sha2_256_digest(data),
            Self::Blake3_512 => digest::blake3_512_digest(data),
            Self::SHA3_512 => digest::sha3_512_digest(data),
            Self::Blake2B512 => digest::blake2b_512_digest(data),
            Self::SHA2_512 => digest::sha2_512_digest(data),
        }
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingPrefix {
        SelfAddressingPrefix::new(self.to_owned(), self.digest(data))
    }
}
