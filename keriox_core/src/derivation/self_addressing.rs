use crate::event_parsing::codes::self_addressing::SelfAddressing as CesrSelfAddressing;
use crate::prefix::SelfAddressingPrefix;
use blake2::{Blake2b, Digest, VarBlake2b, VarBlake2s};
use blake3;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};

//     sha2::{Sha256, Sha512},
//     sha3::{Sha3_256, Sha3_512},
//     Digest,
// };

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

impl Into<CesrSelfAddressing> for SelfAddressing {
    fn into(self) -> CesrSelfAddressing {
        match self {
            SelfAddressing::Blake3_256 => CesrSelfAddressing::Blake3_256,
            SelfAddressing::Blake2B256(a) => CesrSelfAddressing::Blake2B256(a),
            SelfAddressing::Blake2S256(a) => CesrSelfAddressing::Blake2S256(a),
            SelfAddressing::SHA3_256 => CesrSelfAddressing::SHA3_256,
            SelfAddressing::SHA2_256 => CesrSelfAddressing::SHA2_256,
            SelfAddressing::Blake3_512 => CesrSelfAddressing::Blake3_512,
            SelfAddressing::SHA3_512 => CesrSelfAddressing::SHA3_512,
            SelfAddressing::Blake2B512 => CesrSelfAddressing::Blake2B512,
            SelfAddressing::SHA2_512 => CesrSelfAddressing::SHA2_512,
        }
    }
}

impl From<CesrSelfAddressing> for SelfAddressing {
    fn from(csa: CesrSelfAddressing) -> Self {
        match csa {
            CesrSelfAddressing::Blake3_256 => SelfAddressing::Blake3_256,
            CesrSelfAddressing::Blake2B256(a) => SelfAddressing::Blake2B256(a),
            CesrSelfAddressing::Blake2S256(a) => SelfAddressing::Blake2S256(a),
            CesrSelfAddressing::SHA3_256 => SelfAddressing::SHA3_256,
            CesrSelfAddressing::SHA2_256 => SelfAddressing::SHA2_256,
            CesrSelfAddressing::Blake3_512 => SelfAddressing::Blake3_512,
            CesrSelfAddressing::SHA3_512 => SelfAddressing::SHA3_512,
            CesrSelfAddressing::Blake2B512 => SelfAddressing::Blake2B512,
            CesrSelfAddressing::SHA2_512 => SelfAddressing::SHA2_512,
        }
    }
}

impl SelfAddressing {
    pub fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Blake3_256 => blake3_256_digest(data),
            Self::Blake2B256(key) => blake2b_256_digest(data, key),
            Self::Blake2S256(key) => blake2s_256_digest(data, key),
            Self::SHA3_256 => sha3_256_digest(data),
            Self::SHA2_256 => sha2_256_digest(data),
            Self::Blake3_512 => blake3_512_digest(data),
            Self::SHA3_512 => sha3_512_digest(data),
            Self::Blake2B512 => blake2b_512_digest(data),
            Self::SHA2_512 => sha2_512_digest(data),
        }
    }

    pub fn derive(&self, data: &[u8]) -> SelfAddressingPrefix {
        SelfAddressingPrefix::new(self.to_owned(), self.digest(data))
    }
}

fn blake3_256_digest(input: &[u8]) -> Vec<u8> {
    blake3::hash(input).as_bytes().to_vec()
}

fn blake2s_256_digest(input: &[u8], key: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = VarBlake2s::new_keyed(key, 256);
    hasher.update(input);
    hasher.finalize_boxed().to_vec()
}

// TODO it seems that blake2b is always defined as outputting 512 bits?
// TODO updated -> is this the one?
fn blake2b_256_digest(input: &[u8], key: &[u8]) -> Vec<u8> {
    use blake2::digest::{Update, VariableOutput};
    let mut hasher = VarBlake2b::new_keyed(key, 256);
    hasher.update(input);
    hasher.finalize_boxed().to_vec()
}

fn blake3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut out = [0u8; 64];
    let mut h = blake3::Hasher::new();
    h.update(input);
    h.finalize_xof().fill(&mut out);
    out.to_vec()
}

fn blake2b_512_digest(input: &[u8]) -> Vec<u8> {
    let mut hasher = Blake2b::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}

fn sha3_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(input);
    h.finalize().to_vec()
}

fn sha2_256_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(input);
    h.finalize().to_vec()
}

fn sha3_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha3_512::new();
    h.update(input);
    h.finalize().to_vec()
}

fn sha2_512_digest(input: &[u8]) -> Vec<u8> {
    let mut h = Sha512::new();
    h.update(input);
    h.finalize().to_vec()
}
