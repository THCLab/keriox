use cesrox::primitives::{
    codes::attached_signature_code::{AttachedSignatureCode, Index as CesrIndex},
    CesrPrimitive, Digest, Identifier, IdentifierCode, IndexedSignature as CesrIndexedSignature,
    PublicKey, Signature,
};
use said::SelfAddressingIdentifier;

use crate::{
    event::sections::seal::{EventSeal, SourceSeal},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use super::attached_signature::Index;

impl From<CesrIndexedSignature> for IndexedSignature {
    fn from((code, value): CesrIndexedSignature) -> Self {
        match code.index {
            CesrIndex::BothSame(i) => {
                IndexedSignature::new_both_same(SelfSigningPrefix::new(code.code, value), i)
            }
            CesrIndex::Dual(i, pi) => {
                IndexedSignature::new_both_diffrent(SelfSigningPrefix::new(code.code, value), i, pi)
            }
            CesrIndex::BigDual(i, pi) => {
                IndexedSignature::new_both_diffrent(SelfSigningPrefix::new(code.code, value), i, pi)
            }
            CesrIndex::CurrentOnly(i) => {
                IndexedSignature::new_current_only(SelfSigningPrefix::new(code.code, value), i)
            }
            CesrIndex::BigCurrentOnly(i) => {
                IndexedSignature::new_current_only(SelfSigningPrefix::new(code.code, value), i)
            }
        }
    }
}

impl From<CesrIndex> for Index {
    fn from(value: CesrIndex) -> Self {
        match value {
            CesrIndex::BothSame(i) => Index::BothSame(i),
            CesrIndex::Dual(i, pi) | CesrIndex::BigDual(i, pi) => Index::BothDifferent(i, pi),
            CesrIndex::CurrentOnly(i) | CesrIndex::BigCurrentOnly(i) => Index::CurrentOnly(i),
        }
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
        SourceSeal::new(sn, digest.into())
    }
}

impl From<(Digest, u64, Digest)> for EventSeal {
    fn from((identifier, sn, digest): (Digest, u64, Digest)) -> Self {
        let said: SelfAddressingIdentifier = identifier.into();
        let digest_said: SelfAddressingIdentifier = digest.into();
        EventSeal::new(
            IdentifierPrefix::SelfAddressing(said.into()),
            sn,
            digest_said.into(),
        )
    }
}

impl From<(PublicKey, u64, Digest)> for EventSeal {
    fn from((identifier, sn, digest): (PublicKey, u64, Digest)) -> Self {
        let digest_said: SelfAddressingIdentifier = digest.into();
        EventSeal::new(
            IdentifierPrefix::Basic(identifier.into()),
            sn,
            digest_said.into(),
        )
    }
}

impl From<Identifier> for IdentifierPrefix {
    fn from(identifier: Identifier) -> Self {
        match identifier.0 {
            IdentifierCode::Basic(bp) => IdentifierPrefix::Basic(BasicPrefix::new(
                bp,
                crate::keys::PublicKey::new(identifier.1),
            )),
            IdentifierCode::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(
                SelfAddressingIdentifier::new(sa.into(), identifier.1).into(),
            ),
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
            AttachedSignatureCode::new(self.signature.get_code(), (&self.index).into()),
            self.derivative(),
        )
    }
}

impl Into<CesrIndex> for &Index {
    fn into(self) -> CesrIndex {
        match self {
            Index::CurrentOnly(i) => {
                if *i < 64 {
                    CesrIndex::CurrentOnly(*i)
                } else {
                    CesrIndex::BigCurrentOnly(*i)
                }
            }
            Index::BothSame(i) => CesrIndex::BothSame(*i),
            Index::BothDifferent(i, pi) => {
                if *i < 64 {
                    CesrIndex::Dual(*i, *pi)
                } else {
                    CesrIndex::BigDual(*i, *pi)
                }
            }
        }
    }
}

impl Into<Identifier> for IdentifierPrefix {
    fn into(self) -> Identifier {
        match &self {
            IdentifierPrefix::Basic(bp) => {
                (IdentifierCode::Basic(bp.get_code()), self.derivative())
            }
            IdentifierPrefix::SelfAddressing(sa) => (
                IdentifierCode::SelfAddressing((&sa.said.derivation).into()),
                self.derivative(),
            ),
            IdentifierPrefix::SelfSigning(_ss) => todo!(),
        }
    }
}
