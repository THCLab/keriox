use cesrox::primitives::{
    codes::attached_signature_code::AttachedSignatureCode, CesrPrimitive, Digest, Identifier,
    IdentifierCode, IndexedSignature as CesrIndexedSignature, PublicKey, Signature,
};
use sai::SelfAddressingPrefix;

use crate::{
    event::sections::seal::{EventSeal, SourceSeal},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

impl From<CesrIndexedSignature> for IndexedSignature {
    fn from((code, value): CesrIndexedSignature) -> Self {
        IndexedSignature::new_both_same(SelfSigningPrefix::new(code.code, value), code.index)
    }
}

impl From<PublicKey> for BasicPrefix {
    fn from(pk: PublicKey) -> Self {
        BasicPrefix::new(pk.0, crate::keys::PublicKey::new(pk.1))
    }
}

impl From<Signature> for SelfSigningPrefix {
    fn from((code, value): Signature) -> Self {
        SelfSigningPrefix::new(code, value)
    }
}

impl From<(u64, Digest)> for SourceSeal {
    fn from((sn, digest): (u64, Digest)) -> Self {
        SourceSeal {
            sn,
            digest: digest.into(),
        }
    }
}

impl From<(Digest, u64, Digest)> for EventSeal {
    fn from((identifier, sn, digest): (Digest, u64, Digest)) -> Self {
        EventSeal {
            prefix: IdentifierPrefix::SelfAddressing(identifier.into()),
            sn,
            event_digest: digest.into(),
        }
    }
}

impl From<(PublicKey, u64, Digest)> for EventSeal {
    fn from((identifier, sn, digest): (PublicKey, u64, Digest)) -> Self {
        EventSeal {
            prefix: IdentifierPrefix::Basic(identifier.into()),
            sn,
            event_digest: digest.into(),
        }
    }
}

impl From<Identifier> for IdentifierPrefix {
    fn from(identifier: Identifier) -> Self {
        match identifier.0 {
            IdentifierCode::Basic(bp) => IdentifierPrefix::Basic(BasicPrefix::new(
                bp,
                crate::keys::PublicKey::new(identifier.1),
            )),
            IdentifierCode::SelfAddressing(sa) => {
                IdentifierPrefix::SelfAddressing(SelfAddressingPrefix::new(sa.into(), identifier.1))
            }
        }
    }
}

impl Into<Signature> for SelfSigningPrefix {
    fn into(self) -> Signature {
        (self.get_code(), self.derivative())
    }
}

impl Into<PublicKey> for BasicPrefix {
    fn into(self) -> PublicKey {
        (self.get_code(), self.derivative())
    }
}

impl Into<CesrIndexedSignature> for IndexedSignature {
    fn into(self) -> CesrIndexedSignature {
        (
            AttachedSignatureCode::new(self.signature.get_code(), self.index.current()),
            self.derivative(),
        )
    }
}

impl Into<Identifier> for IdentifierPrefix {
    fn into(self) -> Identifier {
        match &self {
            IdentifierPrefix::Basic(bp) => {
                (IdentifierCode::Basic(bp.get_code()), self.derivative())
            }
            IdentifierPrefix::SelfAddressing(sa) => (
                IdentifierCode::SelfAddressing((&sa.derivation).into()),
                self.derivative(),
            ),
            IdentifierPrefix::SelfSigning(_ss) => todo!(),
        }
    }
}
