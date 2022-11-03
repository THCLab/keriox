use serde::{Deserialize, Serialize};

use crate::event_parsing::codes::basic::Basic as CesrBasic;
use crate::{keys::PublicKey, prefix::BasicPrefix};

/// Basic Derivations
///
/// Basic prefix derivation is just a public key (2.3.1)
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize, Hash, Eq)]
pub enum Basic {
    ECDSAsecp256k1NT,
    ECDSAsecp256k1,
    Ed25519NT,
    Ed25519,
    Ed448NT,
    Ed448,
    X25519,
    X448,
}

impl Into<CesrBasic> for Basic {
    fn into(self) -> CesrBasic {
        match self {
            Basic::ECDSAsecp256k1NT => CesrBasic::ECDSAsecp256k1NT,
            Basic::ECDSAsecp256k1 => CesrBasic::ECDSAsecp256k1,
            Basic::Ed25519NT => CesrBasic::Ed25519NT,
            Basic::Ed25519 => CesrBasic::Ed25519,
            Basic::Ed448NT => CesrBasic::Ed448NT,
            Basic::Ed448 => CesrBasic::Ed448,
            Basic::X25519 => CesrBasic::X25519,
            Basic::X448 => CesrBasic::X448,
        }
    }
}

impl From<CesrBasic> for Basic {
    fn from(cb: CesrBasic) -> Self {
        match cb {
            CesrBasic::ECDSAsecp256k1NT => Basic::ECDSAsecp256k1NT,
            CesrBasic::ECDSAsecp256k1 => Basic::ECDSAsecp256k1,
            CesrBasic::Ed25519NT => Basic::Ed25519NT,
            CesrBasic::Ed25519 => Basic::Ed25519,
            CesrBasic::Ed448NT => Basic::Ed448NT,
            CesrBasic::Ed448 => Basic::Ed448,
            CesrBasic::X25519 => Basic::X25519,
            CesrBasic::X448 => Basic::X448,
        }
    }
}

impl Basic {
    pub fn derive(&self, public_key: PublicKey) -> BasicPrefix {
        BasicPrefix::new(*self, public_key)
    }

    /// Non transferable means that the public key is always the current public key.
    /// Transferable means that the public key might have changed and
    /// you need to request KEL to obtain the newest one.
    pub fn is_transferable(&self) -> bool {
        match self {
            Basic::ECDSAsecp256k1NT | Basic::Ed25519NT | Basic::Ed448NT => false,
            _ => true,
        }
    }
}
