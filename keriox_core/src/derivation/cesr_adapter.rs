use crate::event_parsing::codes::self_addressing::SelfAddressing as CesrSelfAddressing;

use super::SelfAddressing;

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

