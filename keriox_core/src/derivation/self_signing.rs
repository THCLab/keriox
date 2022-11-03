use crate::event_parsing::codes::self_signing::SelfSigning as CesrSelfSigning;
use crate::prefix::SelfSigningPrefix;

/// Self Signing Derivations
///
/// A self signing prefix derivation outputs a signature as its derivative (2.3.5)
#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
pub enum SelfSigning {
    Ed25519Sha512,
    ECDSAsecp256k1Sha256,
    Ed448,
}

impl Into<CesrSelfSigning> for SelfSigning {
    fn into(self) -> CesrSelfSigning {
        match self {
            SelfSigning::Ed25519Sha512 => CesrSelfSigning::Ed25519Sha512,
            SelfSigning::ECDSAsecp256k1Sha256 => CesrSelfSigning::ECDSAsecp256k1Sha256,
            SelfSigning::Ed448 => CesrSelfSigning::Ed448,
        }
    }
}

impl From<CesrSelfSigning> for SelfSigning {
    fn from(css: CesrSelfSigning) -> Self {
        match css {
            CesrSelfSigning::Ed25519Sha512 => SelfSigning::Ed25519Sha512,
            CesrSelfSigning::ECDSAsecp256k1Sha256 => SelfSigning::ECDSAsecp256k1Sha256,
            CesrSelfSigning::Ed448 => SelfSigning::Ed448,
        }
    }
}

impl SelfSigning {
    pub fn derive(&self, sig: Vec<u8>) -> SelfSigningPrefix {
        SelfSigningPrefix::new(*self, sig)
    }
}
