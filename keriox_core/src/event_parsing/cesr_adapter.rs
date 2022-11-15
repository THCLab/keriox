use crate::{
    event::sections::seal::{EventSeal, SourceSeal},
    event_message::signature::Nontransferable,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    sai::SelfAddressingPrefix,
};

use super::{
    codes::attached_signature_code::AttachedSignatureCode,
    group::Group,
    primitives::{
        CesrPrimitive, Digest, Identifier, IdentifierCode, IndexedSignature, PublicKey, Signature,
    },
};

impl From<IndexedSignature> for AttachedSignaturePrefix {
    fn from((code, value): IndexedSignature) -> Self {
        AttachedSignaturePrefix {
            index: code.index,
            signature: SelfSigningPrefix::new(code.code, value),
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

impl From<Digest> for SelfAddressingPrefix {
    fn from((code, digest): Digest) -> Self {
        SelfAddressingPrefix::new(code.into(), digest)
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

impl Into<Digest> for &SelfAddressingPrefix {
    fn into(self) -> Digest {
        (self.derivation.clone().into(), self.derivative())
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

impl Into<IndexedSignature> for AttachedSignaturePrefix {
    fn into(self) -> IndexedSignature {
        (
            AttachedSignatureCode {
                index: self.index,
                code: self.signature.get_code(),
            },
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
                IdentifierCode::SelfAddressing(sa.derivation.clone().into()),
                self.derivative(),
            ),
            IdentifierPrefix::SelfSigning(_ss) => todo!(),
        }
    }
}

impl Into<Group> for Nontransferable {
    fn into(self) -> Group {
        match self {
            Nontransferable::Indexed(indexed) => {
                let signatures = indexed.into_iter().map(|sig| sig.into()).collect();
                Group::IndexedWitnessSignatures(signatures)
            }
            Nontransferable::Couplet(couples) => {
                let couples = couples
                    .into_iter()
                    .map(|(bp, sp)| (bp.into(), sp.into()))
                    .collect();
                Group::NontransferableReceiptCouples(couples)
            }
        }
    }
}

impl Into<Group> for crate::event_message::signature::Signature {
    fn into(self) -> Group {
        match self {
            crate::event_message::signature::Signature::Transferable(seal, signature) => {
                let signatures: Vec<IndexedSignature> =
                    signature.into_iter().map(|sig| sig.into()).collect();
                match seal {
                    crate::event_message::signature::SignerData::EventSeal(EventSeal {
                        prefix,
                        sn,
                        event_digest,
                    }) => Group::TransferableIndexedSigGroups(vec![(
                        prefix.into(),
                        sn,
                        (&event_digest).into(),
                        signatures,
                    )]),
                    crate::event_message::signature::SignerData::LastEstablishment(id) => {
                        Group::LastEstSignaturesGroups(vec![(id.into(), signatures)])
                    }
                    crate::event_message::signature::SignerData::JustSignatures => {
                        Group::IndexedControllerSignatures(signatures)
                    }
                }
            }
            crate::event_message::signature::Signature::NonTransferable(nt) => nt.into(),
        }
    }
}
