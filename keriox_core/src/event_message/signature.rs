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
    Transferable(SignerData, Vec<AttachedSignaturePrefix>),
    NonTransferable(BasicPrefix, SelfSigningPrefix),
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
            Signature::NonTransferable(id, _) => Some(IdentifierPrefix::Basic(id.clone())),
        }
    }
}

impl Into<Attachment> for &Signature {
    fn into(self) -> Attachment {
        match self {
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

impl TryFrom<Attachment> for Signature {
    type Error = Error;

    fn try_from(value: Attachment) -> Result<Self, Self::Error> {
        match value {
            // TODO:
            Attachment::AttachedSignatures(sigs) => {
                Ok(Signature::Transferable(SignerData::JustSignatures, sigs))
            }
            Attachment::ReceiptCouplets(sigs) => Ok(Signature::NonTransferable(
                sigs[0].0.clone(),
                sigs[0].1.clone(),
            )),
            Attachment::LastEstSignaturesGroups(sigs) => Ok(Signature::Transferable(
                SignerData::LastEstablishment(sigs[0].0.clone()),
                sigs[0].1.clone(),
            )),
            Attachment::SealSignaturesGroups(sigs) => {
                // TODO: what if more than one?
                Ok(sigs
                    .into_iter()
                    .map(|(seal, sig)| Signature::Transferable(SignerData::EventSeal(seal), sig))
                    .next()
                    .unwrap())
            }
            _ => Err(Error::SemanticError("Improper attachment type".into())),
        }
    }
}
