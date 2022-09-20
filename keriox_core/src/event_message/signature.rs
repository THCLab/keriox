use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event::sections::seal::EventSeal,
    event_parsing::Attachment,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::event_storage::EventStorage,
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    /// Created by transferable identifier
    Transferable(SignerData, Vec<AttachedSignaturePrefix>),
    /// Created by nontransferable identifier
    NonTransferable(Nontransferable),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Nontransferable {
    Indexed(Vec<AttachedSignaturePrefix>),
    Couplet(BasicPrefix, SelfSigningPrefix),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SignerData {
    EventSeal(EventSeal),
    LastEstablishment(IdentifierPrefix),
    JustSignatures,
}

impl SignerData {
    pub fn get_signer(&self) -> Option<IdentifierPrefix> {
        match self {
            SignerData::EventSeal(seal) => Some(seal.prefix.clone()),
            SignerData::LastEstablishment(id) => Some(id.clone()),
            SignerData::JustSignatures => None,
        }
    }
}

impl Signature {
    pub fn get_signer(&self) -> Option<IdentifierPrefix> {
        match self {
            Signature::Transferable(signer_data, _) => signer_data.get_signer(),
            Signature::NonTransferable(Nontransferable::Couplet(id, _)) => {
                Some(IdentifierPrefix::Basic(id.clone()))
            }
            Signature::NonTransferable(Nontransferable::Indexed(_)) => None,
        }
    }

    pub fn verify(&self, data: &[u8], storage: &EventStorage) -> Result<bool, Error> {
        match self {
            Signature::Transferable(_sigd, sigs) => {
                let kc = storage
                    .get_state(
                        &self
                            .get_signer()
                            .ok_or(Error::SemanticError("Uknown signer".into()))?,
                    )?
                    .ok_or_else(|| Error::SemanticError("No signer identifier in db".into()))?
                    .current;
                kc.verify(data, &sigs)
            }
            Signature::NonTransferable(Nontransferable::Couplet(id, sig)) => id.verify(data, &sig),
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                Err(Error::SemanticError("Uknown signer".into()))
            }
        }
    }
}

impl From<&Signature> for Attachment {
    fn from(signature: &Signature) -> Self {
        match signature {
            Signature::Transferable(signer_data, sig) => match signer_data {
                SignerData::EventSeal(seal) => {
                    Attachment::SealSignaturesGroups(vec![(seal.clone(), sig.clone())])
                }
                SignerData::LastEstablishment(id) => {
                    Attachment::LastEstSignaturesGroups(vec![(id.clone(), sig.clone())])
                }
                SignerData::JustSignatures => Attachment::AttachedSignatures(sig.clone()),
            },
            Signature::NonTransferable(Nontransferable::Couplet(bp, sig)) => {
                Attachment::ReceiptCouplets(vec![(bp.clone(), sig.clone())])
            }
            Signature::NonTransferable(Nontransferable::Indexed(sigs)) => {
                Attachment::AttachedWitnessSignatures(sigs.clone())
            }
        }
    }
}

pub fn signatures_into_attachments(sigs: &[Signature]) -> Vec<Attachment> {
    // Group same type of signature in one attachment
    let (trans_seal, trans_last, nontrans, indexed, witness_indexed) =
        sigs.into_iter().cloned().fold(
            (vec![], vec![], vec![], vec![], vec![]),
            |(mut trans_seal, mut trans_last, mut nontrans, mut indexed, mut witness_indexed),
             sig| {
                match sig {
                    Signature::Transferable(SignerData::EventSeal(seal), sig) => {
                        trans_seal.push((seal, sig))
                    }
                    Signature::Transferable(SignerData::LastEstablishment(id), sig) => {
                        trans_last.push((id, sig))
                    }
                    Signature::Transferable(SignerData::JustSignatures, mut sig) => {
                        indexed.append(&mut sig)
                    }
                    Signature::NonTransferable(Nontransferable::Couplet(bp, sp)) => {
                        nontrans.push((bp, sp))
                    }
                    Signature::NonTransferable(Nontransferable::Indexed(mut sigs)) => {
                        witness_indexed.append(&mut sigs)
                    }
                };
                (trans_seal, trans_last, nontrans, indexed, witness_indexed)
            },
        );

    let mut attachments = vec![];
    if !trans_seal.is_empty() {
        attachments.push(Attachment::SealSignaturesGroups(trans_seal));
    }
    if !trans_last.is_empty() {
        attachments.push(Attachment::LastEstSignaturesGroups(trans_last));
    }
    if !nontrans.is_empty() {
        attachments.push(Attachment::ReceiptCouplets(nontrans));
    };
    if !indexed.is_empty() {
        attachments.push(Attachment::AttachedSignatures(indexed));
    };
    if !witness_indexed.is_empty() {
        attachments.push(Attachment::AttachedWitnessSignatures(witness_indexed));
    };
    attachments
}

impl TryFrom<Attachment> for Vec<Signature> {
    type Error = Error;

    fn try_from(value: Attachment) -> Result<Self, Self::Error> {
        match value {
            Attachment::AttachedSignatures(sigs) => Ok(vec![Signature::Transferable(
                SignerData::JustSignatures,
                sigs,
            )]),
            Attachment::ReceiptCouplets(sigs) => Ok(sigs
                .into_iter()
                .map(|(bp, sp)| Signature::NonTransferable(Nontransferable::Couplet(bp, sp)))
                .collect()),
            Attachment::LastEstSignaturesGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(id, sigs)| Signature::Transferable(SignerData::LastEstablishment(id), sigs))
                .collect()),
            Attachment::SealSignaturesGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(seal, sig)| Signature::Transferable(SignerData::EventSeal(seal), sig))
                .collect()),
            Attachment::AttachedWitnessSignatures(sigs) => Ok(vec![Signature::NonTransferable(
                Nontransferable::Indexed(sigs),
            )]),
            _ => Err(Error::SemanticError("Improper attachment type".into())),
        }
    }
}
