use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event::sections::seal::EventSeal,
    event_parsing::Attachment,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    /// Created by transferable identifier
    Transferable(SignerData, Vec<AttachedSignaturePrefix>),
    /// Created by nontransferable identifier
    NonTransferable(BasicPrefix, SelfSigningPrefix),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum SignerData {
    EventSeal(EventSeal),
    LastEstablishment(IdentifierPrefix),
    // Signer id should be taken from event
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
            Signature::NonTransferable(id, _) => Some(IdentifierPrefix::Basic(id.clone())),
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
            Signature::NonTransferable(bp, sig) => {
                Attachment::ReceiptCouplets(vec![(bp.clone(), sig.clone())])
            }
        }
    }
}

pub fn signatures_into_attachments(sigs: &[Signature]) -> Vec<Attachment> {
    // Group same type of signature in one attachment
    let (trans_seal, trans_last, nontrans, indexed) = sigs.into_iter().cloned().fold(
        (vec![], vec![], vec![], vec![]),
        |(mut trans_seal, mut trans_last, mut nontrans, mut indexed), sig| {
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
                Signature::NonTransferable(bp, sp) => nontrans.push((bp, sp)),
            };
            (trans_seal, trans_last, nontrans, indexed)
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
                .map(|(bp, sp)| Signature::NonTransferable(bp, sp))
                .collect()),
            Attachment::LastEstSignaturesGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(id, sigs)| Signature::Transferable(SignerData::LastEstablishment(id), sigs))
                .collect()),
            Attachment::SealSignaturesGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(seal, sig)| Signature::Transferable(SignerData::EventSeal(seal), sig))
                .collect()),
            _ => Err(Error::SemanticError("Improper attachment type".into())),
        }
    }
}
