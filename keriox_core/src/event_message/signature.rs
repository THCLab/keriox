use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event::sections::seal::EventSeal,
    event_parsing::group::Group,
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
    Couplet(Vec<(BasicPrefix, SelfSigningPrefix)>),
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
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => {
                // TODO
                Some(IdentifierPrefix::Basic(couplets[0].0.clone()))
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
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => Ok(couplets
                .iter()
                .all(|(id, sig)| id.verify(data, &sig).unwrap())),
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                Err(Error::SemanticError("Uknown signer".into()))
            }
        }
    }
}

pub fn signatures_into_groups(sigs: &[Signature]) -> Vec<Group> {
    // Group same type of signature in one attachment
    let (trans_seal, trans_last, nontrans, indexed, witness_indexed) =
        sigs.into_iter().cloned().fold(
            (vec![], vec![], vec![], vec![], vec![]),
            |(mut trans_seal, mut trans_last, mut nontrans, mut indexed, mut witness_indexed),
             sig| {
                match sig {
                    Signature::Transferable(SignerData::EventSeal(seal), sig) => trans_seal.push((
                        seal.prefix.into(),
                        seal.sn,
                        (&seal.event_digest).into(),
                        sig.into_iter().map(|sig| sig.into()).collect(),
                    )),
                    Signature::Transferable(SignerData::LastEstablishment(id), sig) => trans_last
                        .push((id.into(), sig.into_iter().map(|sig| sig.into()).collect())),
                    Signature::Transferable(SignerData::JustSignatures, mut sig) => {
                        indexed.append(&mut sig.into_iter().map(|sig| sig.into()).collect())
                    }
                    Signature::NonTransferable(Nontransferable::Couplet(couplets)) => nontrans
                        .append(
                            &mut couplets
                                .into_iter()
                                .map(|(bp, sp)| (bp.into(), sp.into()))
                                .collect(),
                        ),
                    Signature::NonTransferable(Nontransferable::Indexed(mut sigs)) => {
                        witness_indexed
                            .append(&mut sigs.into_iter().map(|sig| sig.into()).collect())
                    }
                };
                (trans_seal, trans_last, nontrans, indexed, witness_indexed)
            },
        );

    let mut attachments = vec![];
    if !trans_seal.is_empty() {
        attachments.push(Group::TransferableIndexedSigGroups(trans_seal));
    }
    if !trans_last.is_empty() {
        attachments.push(Group::LastEstSignaturesGroups(trans_last));
    }
    if !nontrans.is_empty() {
        attachments.push(Group::NontransferableReceiptCouples(nontrans));
    };
    if !indexed.is_empty() {
        attachments.push(Group::IndexedControllerSignatures(indexed));
    };
    if !witness_indexed.is_empty() {
        attachments.push(Group::IndexedWitnessSignatures(witness_indexed));
    };
    attachments
}

impl TryFrom<Group> for Vec<Signature> {
    type Error = Error;

    fn try_from(value: Group) -> Result<Self, Self::Error> {
        match value {
            Group::IndexedControllerSignatures(sigs) => {
                let signatures = sigs.into_iter().map(|sig| sig.into()).collect();
                Ok(vec![Signature::Transferable(
                    SignerData::JustSignatures,
                    signatures,
                )])
            }
            Group::NontransferableReceiptCouples(sigs) => {
                let signatures = sigs
                    .into_iter()
                    .map(|(bp, sp)| (bp.into(), sp.into()))
                    .collect();
                Ok(vec![Signature::NonTransferable(Nontransferable::Couplet(
                    signatures,
                ))])
            }
            Group::LastEstSignaturesGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(id, sigs)| {
                    let signatures = sigs.into_iter().map(|sig| sig.into()).collect();
                    Signature::Transferable(SignerData::LastEstablishment(id.into()), signatures)
                })
                .collect()),
            Group::TransferableIndexedSigGroups(sigs) => Ok(sigs
                .into_iter()
                .map(|(id, sn, digest, sigs)| {
                    let signatures = sigs.into_iter().map(|sig| sig.into()).collect();
                    Signature::Transferable(
                        SignerData::EventSeal(EventSeal {
                            prefix: id.into(),
                            sn,
                            event_digest: digest.into(),
                        }),
                        signatures,
                    )
                })
                .collect()),
            Group::IndexedWitnessSignatures(sigs) => {
                let signatures = sigs.into_iter().map(|sig| sig.into()).collect();
                Ok(vec![Signature::NonTransferable(Nontransferable::Indexed(
                    signatures,
                ))])
            }
            _ => Err(Error::SemanticError("Improper attachment type".into())),
        }
    }
}
