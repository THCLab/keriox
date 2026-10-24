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
            signature: SelfSigningPrefix::new(signature.code.code, signature.raw)?,
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

impl TryFrom<PublicKey> for BasicPrefix {
    type Error = Error;

    fn try_from(pk: PublicKey) -> Result<Self, Self::Error> {
        BasicPrefix::new(pk.code, crate::keys::PublicKey::new(pk.raw))
    }
}

impl TryFrom<Signature> for SelfSigningPrefix {
    type Error = Error;

    fn try_from(signature: Signature) -> Result<Self, Self::Error> {
        SelfSigningPrefix::new(signature.code, signature.raw)
    }
}

/// Splits the CESR couple of a receipt by a non-transferable identifier
/// into the identifier and its signature.
pub fn from_receipt_couple(
    couple: NontransReceiptCouple,
) -> Result<(BasicPrefix, SelfSigningPrefix), Error> {
    Ok((couple.key.try_into()?, couple.signature.try_into()?))
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
            seal.prefix.try_into()?,
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

impl TryFrom<Identifier> for IdentifierPrefix {
    type Error = Error;

    fn try_from(identifier: Identifier) -> Result<Self, Self::Error> {
        Ok(match identifier.code {
            IdentifierCode::Basic(bp) => IdentifierPrefix::Basic(BasicPrefix::new(
                bp,
                crate::keys::PublicKey::new(identifier.raw),
            )?),
            IdentifierCode::SelfAddressing(sa) => IdentifierPrefix::SelfAddressing(
                SelfAddressingIdentifier::new(sa.into(), identifier.raw).into(),
            ),
        })
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

#[cfg(test)]
mod supported_codes {
    use cesrox::primitives::codes::{basic::Basic, seed::SeedCode, self_signing::SelfSigning};

    use crate::{
        keys::PublicKey,
        prefix::{BasicPrefix, SeedPrefix, SelfSigningPrefix},
    };

    // cesrox's code tables are non-exhaustive, so the constructors return a
    // Result: a code cesrox adds later is refused instead of panicking the
    // parser of a remote stream. Every code cesrox has today is supported.

    #[test]
    fn every_public_key_code_makes_a_prefix() {
        for code in [
            Basic::ECDSAsecp256k1Nontrans,
            Basic::ECDSAsecp256k1,
            Basic::Ed25519Nontrans,
            Basic::Ed25519,
            Basic::Ed448Nontrans,
            Basic::Ed448,
            Basic::X25519,
            Basic::X448,
            Basic::ECDSA256r1Nontrans,
            Basic::ECDSA256r1,
        ] {
            let prefix = BasicPrefix::new(code.clone(), PublicKey::new(vec![1; 32]));
            assert!(prefix.is_ok(), "{code:?}: {prefix:?}");
        }
    }

    #[test]
    fn every_signature_code_makes_a_prefix() {
        for code in [
            SelfSigning::Ed25519Sha512,
            SelfSigning::ECDSAsecp256k1Sha256,
            SelfSigning::Ed448,
            SelfSigning::ECDSA256r1Sha256,
        ] {
            let prefix = SelfSigningPrefix::new(code.clone(), vec![1; 64]);
            assert!(prefix.is_ok(), "{code:?}: {prefix:?}");
        }
    }

    #[test]
    fn every_seed_code_makes_a_seed() {
        for code in [
            SeedCode::RandomSeed256Ed25519,
            SeedCode::RandomSeed256ECDSAsecp256k1,
            SeedCode::RandomSeed448,
            SeedCode::RandomSeed256ECDSA256r1,
        ] {
            let seed = SeedPrefix::new(code.clone(), vec![1; 32]);
            assert!(seed.is_ok(), "{code:?}: {seed:?}");
        }
    }
}
