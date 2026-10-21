use cesrox::{
    group::{NontransReceiptCouple, SealSourceCouple, TransIdxSigGroup},
    primitives::{
        codes::attached_signature_code::{AttachedSignatureCode, Index as CesrIndex},
        AnchoringEventSeal, CesrPrimitive, Identifier, IdentifierCode,
        IndexedSignature as CesrIndexedSignature, PublicKey, Signature,
    },
};
use said::SelfAddressingIdentifier;

use crate::{
    event::sections::seal::{EventSeal, SourceSeal},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
};

use super::{attached_signature::Index, error::Error};

impl TryFrom<CesrIndexedSignature> for IndexedSignature {
    type Error = Error;

    fn try_from(signature: CesrIndexedSignature) -> Result<Self, Self::Error> {
        let index = signature.code.index.try_into()?;
        Ok(IndexedSignature {
            index,
            signature: SelfSigningPrefix::new(signature.code.code, signature.raw),
        })
    }
}

impl TryFrom<CesrIndex> for Index {
    type Error = Error;

    fn try_from(value: CesrIndex) -> Result<Self, Self::Error> {
        let narrow = |i: u32| u16::try_from(i).map_err(|_| Error::IndexOutOfRange(i));
        Ok(match value {
            CesrIndex::BothSame(i) => Index::BothSame(narrow(i)?),
            CesrIndex::Dual(i, pi) | CesrIndex::BigDual(i, pi) => {
                Index::BothDifferent(narrow(i)?, narrow(pi)?)
            }
            CesrIndex::CurrentOnly(i) | CesrIndex::BigCurrentOnly(i) => {
                Index::CurrentOnly(narrow(i)?)
            }
        })
    }
}

impl From<PublicKey> for BasicPrefix {
    fn from(pk: PublicKey) -> Self {
        BasicPrefix::new(pk.code, crate::keys::PublicKey::new(pk.raw))
    }
}

impl From<Signature> for SelfSigningPrefix {
    fn from(signature: Signature) -> Self {
        SelfSigningPrefix::new(signature.code, signature.raw)
    }
}

/// Splits the CESR couple of a receipt by a non-transferable identifier
/// into the identifier and its signature.
pub fn from_receipt_couple(couple: NontransReceiptCouple) -> (BasicPrefix, SelfSigningPrefix) {
    (couple.key.into(), couple.signature.into())
}

/// Builds the CESR couple of a receipt by a non-transferable identifier.
pub fn receipt_couple(key: BasicPrefix, signature: SelfSigningPrefix) -> NontransReceiptCouple {
    NontransReceiptCouple {
        key: key.into(),
        signature: signature.into(),
    }
}

fn sn_from_cesr(sn: u128) -> Result<u64, Error> {
    u64::try_from(sn).map_err(|_| Error::SnOutOfRange(sn))
}

impl TryFrom<SealSourceCouple> for SourceSeal {
    type Error = Error;

    fn try_from(couple: SealSourceCouple) -> Result<Self, Self::Error> {
        Ok(SourceSeal::new(
            sn_from_cesr(couple.sn)?,
            couple.digest.into(),
        ))
    }
}

impl TryFrom<AnchoringEventSeal> for EventSeal {
    type Error = Error;

    fn try_from(seal: AnchoringEventSeal) -> Result<Self, Self::Error> {
        let digest: SelfAddressingIdentifier = seal.digest.into();
        Ok(EventSeal::new(
            seal.prefix.into(),
            sn_from_cesr(seal.sn)?,
            digest,
        ))
    }
}

impl From<SourceSeal> for SealSourceCouple {
    fn from(seal: SourceSeal) -> Self {
        SealSourceCouple {
            sn: seal.sn.into(),
            digest: seal.digest.said.into(),
        }
    }
}

impl From<EventSeal> for AnchoringEventSeal {
    fn from(seal: EventSeal) -> Self {
        let digest = seal.event_digest();
        AnchoringEventSeal {
            prefix: seal.prefix.into(),
            sn: seal.sn.into(),
            digest: digest.into(),
        }
    }
}

/// The establishment event a transferable signer signed with and the
/// signatures, from a `-X` group entry.
pub fn from_trans_idx_sig_group(
    group: TransIdxSigGroup,
) -> Result<(EventSeal, Vec<CesrIndexedSignature>), Error> {
    let seal = EventSeal::try_from(AnchoringEventSeal {
        prefix: group.prefix,
        sn: group.sn,
        digest: group.digest,
    })?;
    Ok((seal, group.signatures))
}

/// A `-X` group entry for signatures made with the keys of `seal`'s event.
pub fn trans_idx_sig_group(
    seal: EventSeal,
    signatures: Vec<CesrIndexedSignature>,
) -> TransIdxSigGroup {
    let AnchoringEventSeal { prefix, sn, digest } = seal.into();
    TransIdxSigGroup {
        prefix,
        sn,
        digest,
        signatures,
    }
}

impl From<Identifier> for IdentifierPrefix {
    fn from(identifier: Identifier) -> Self {
        match identifier.code {
            IdentifierCode::Basic(bp) => IdentifierPrefix::Basic(BasicPrefix::new(
                bp,
                crate::keys::PublicKey::new(identifier.raw),
            )),
            IdentifierCode::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(
                SelfAddressingIdentifier::new(sa.into(), identifier.raw).into(),
            ),
        }
    }
}

impl Into<Signature> for SelfSigningPrefix {
    fn into(self) -> Signature {
        Signature::new(self.get_code(), self.derivative())
    }
}

impl Into<PublicKey> for BasicPrefix {
    fn into(self) -> PublicKey {
        PublicKey::new(self.get_code(), self.derivative())
    }
}

impl Into<CesrIndexedSignature> for IndexedSignature {
    fn into(self) -> CesrIndexedSignature {
        CesrIndexedSignature::new(
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
                    CesrIndex::CurrentOnly((*i).into())
                } else {
                    CesrIndex::BigCurrentOnly((*i).into())
                }
            }
            Index::BothSame(i) => CesrIndex::BothSame((*i).into()),
            Index::BothDifferent(i, pi) => {
                if *i < 64 {
                    CesrIndex::Dual((*i).into(), (*pi).into())
                } else {
                    CesrIndex::BigDual((*i).into(), (*pi).into())
                }
            }
        }
    }
}

impl Into<Identifier> for IdentifierPrefix {
    fn into(self) -> Identifier {
        match &self {
            IdentifierPrefix::Basic(bp) => {
                Identifier::new(IdentifierCode::Basic(bp.get_code()), self.derivative())
            }
            IdentifierPrefix::SelfAddressing(sa) => Identifier::new(
                IdentifierCode::SelfAddressing((&sa.said.derivation).into()),
                self.derivative(),
            ),
            IdentifierPrefix::SelfSigning(_ss) => todo!(),
        }
    }
}
