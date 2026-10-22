use cesrox::{
    group::{Group, TransLastIdxSigGroup},
    primitives::IndexedSignature as CesrIndexedSignature,
};
use serde::{Deserialize, Serialize};

use crate::{
    database::EventDatabase,
    error::Error,
    event::sections::seal::EventSeal,
    prefix::{
        cesr_adapter::{
            from_receipt_couple, from_trans_idx_sig_group, receipt_couple, trans_idx_sig_group,
        },
        BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix,
    },
    processor::event_storage::EventStorage,
};

use super::cesr_adapter::{indexed_signatures, ParseError};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    Transferable(SignerData, Vec<IndexedSignature>),
    NonTransferable(Nontransferable),
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(compare(PartialEq), derive(Debug))]
pub enum Nontransferable {
    Indexed(Vec<IndexedSignature>),
    Couplet(Vec<(BasicPrefix, SelfSigningPrefix)>),
}

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Serialize,
    rkyv::Deserialize,
    rkyv::Archive,
)]
#[rkyv(derive(Debug))]
pub enum Transferable {
    Seal(EventSeal, Vec<IndexedSignature>),
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
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => couplets
                .first()
                .map(|(signer, _signature)| IdentifierPrefix::Basic(signer.clone())),
            Signature::NonTransferable(Nontransferable::Indexed(_)) => None,
        }
    }

    pub fn verify<D: EventDatabase>(
        &self,
        data: &[u8],
        storage: &EventStorage<D>,
    ) -> Result<bool, Error> {
        match self {
            Signature::Transferable(_sigd, sigs) => {
                let kc = storage
                    .get_state(&self.get_signer().ok_or(Error::MissingSigner)?)
                    .ok_or_else(|| Error::UnknownSigner(self.get_signer().unwrap()))?
                    .current;
                Ok(kc.verify(data, sigs)?)
            }
            Signature::NonTransferable(Nontransferable::Couplet(couplets)) => {
                Ok(couplets_verify(couplets, data))
            }
            Signature::NonTransferable(Nontransferable::Indexed(_sigs)) => {
                Err(Error::MissingSigner)
            }
        }
    }
}

/// Whether every couple signs `data` and there is at least one. A couple
/// whose signature cannot be checked against its key (another algorithm, an
/// unsupported key) comes from the network, so it fails rather than panics.
pub fn couplets_verify(couplets: &[(BasicPrefix, SelfSigningPrefix)], data: &[u8]) -> bool {
    !couplets.is_empty()
        && couplets
            .iter()
            .all(|(signer, signature)| couple_verifies(signer, signature, data))
}

/// Whether a non-transferable couple signs `data`. The couple names no key
/// state, so the KERI specification only lets an AID with a
/// non-transferable code, whose key state is fixed, sign this way: the key
/// of a transferable AID may have been rotated out.
fn couple_verifies(signer: &BasicPrefix, signature: &SelfSigningPrefix, data: &[u8]) -> bool {
    !signer.is_transferable() && signer.verify(data, signature).unwrap_or(false)
}

/// The witness signatures of `receipts` that sign `data`: an indexed
/// signature whose index names one of `witnesses` and is that witness's, and
/// a couple of a non-transferable key whose signature is that key's. The rest are dropped, together
/// with any group left empty, so one bad signature cannot void the others.
pub fn verified_witness_signatures(
    receipts: impl IntoIterator<Item = Nontransferable>,
    witnesses: &[BasicPrefix],
    data: &[u8],
) -> Vec<Nontransferable> {
    receipts
        .into_iter()
        .map(|group| match group {
            Nontransferable::Indexed(sigs) => Nontransferable::Indexed(
                sigs.into_iter()
                    .filter(|sig| {
                        witnesses
                            .get(sig.index.current() as usize)
                            .is_some_and(|witness| {
                                witness.verify(data, &sig.signature).unwrap_or(false)
                            })
                    })
                    .collect(),
            ),
            Nontransferable::Couplet(couplets) => Nontransferable::Couplet(
                couplets
                    .into_iter()
                    .filter(|(signer, signature)| couple_verifies(signer, signature, data))
                    .collect(),
            ),
        })
        .filter(|group| match group {
            Nontransferable::Indexed(sigs) => !sigs.is_empty(),
            Nontransferable::Couplet(couplets) => !couplets.is_empty(),
        })
        .collect()
}

pub fn signatures_into_groups(sigs: &[Signature]) -> Vec<Group> {
    let (trans_seal, trans_last, nontrans, indexed, witness_indexed) = sigs.iter().cloned().fold(
        (vec![], vec![], vec![], vec![], vec![]),
        |(mut trans_seal, mut trans_last, mut nontrans, mut indexed, mut witness_indexed), sig| {
            match sig {
                Signature::Transferable(SignerData::EventSeal(seal), sig) => {
                    trans_seal.push((seal, sig.into_iter().map(|sig| sig.into()).collect()))
                }
                Signature::Transferable(SignerData::LastEstablishment(id), sig) => {
                    trans_last.push((id, sig.into_iter().map(|sig| sig.into()).collect()))
                }
                Signature::Transferable(SignerData::JustSignatures, sig) => {
                    indexed.append(&mut sig.into_iter().map(|sig| sig.into()).collect())
                }
                Signature::NonTransferable(Nontransferable::Couplet(couplets)) => nontrans.append(
                    &mut couplets
                        .into_iter()
                        .map(|(bp, sp)| receipt_couple(bp, sp))
                        .collect(),
                ),
                Signature::NonTransferable(Nontransferable::Indexed(sigs)) => {
                    witness_indexed.append(&mut sigs.into_iter().map(|sig| sig.into()).collect())
                }
            };
            (trans_seal, trans_last, nontrans, indexed, witness_indexed)
        },
    );

    let mut attachments = vec![];

    if !trans_seal.is_empty() {
        attachments.push(Group::TransIdxSigGroups(
            trans_seal
                .into_iter()
                .map(|(seal, sigs)| trans_idx_sig_group(seal, sigs))
                .collect(),
        ));
    }

    if !trans_last.is_empty() {
        attachments.push(Group::TransLastIdxSigGroups(
            trans_last
                .into_iter()
                .map(|(id, signatures)| TransLastIdxSigGroup {
                    prefix: id.into(),
                    signatures,
                })
                .collect(),
        ));
    }

    if !nontrans.is_empty() {
        attachments.push(Group::NontransReceiptCouples(nontrans));
    };
    if !indexed.is_empty() {
        attachments.push(Group::IndexedControllerSignatures(indexed));
    };
    if !witness_indexed.is_empty() {
        attachments.push(Group::IndexedWitnessSignatures(witness_indexed));
    };
    attachments
}

pub fn get_signatures(group: Group) -> Result<Vec<Signature>, ParseError> {
    match group {
        Group::IndexedControllerSignatures(sigs) => {
            let signatures = indexed_signatures(sigs)?;
            Ok(vec![Signature::Transferable(
                SignerData::JustSignatures,
                signatures,
            )])
        }
        Group::NontransReceiptCouples(sigs) => {
            let signatures = sigs.into_iter().map(from_receipt_couple).collect();
            Ok(vec![Signature::NonTransferable(Nontransferable::Couplet(
                signatures,
            ))])
        }
        Group::IndexedWitnessSignatures(sigs) => {
            let signatures = indexed_signatures(sigs)?;
            Ok(vec![Signature::NonTransferable(Nontransferable::Indexed(
                signatures,
            ))])
        }
        Group::AnchoringSeals(_) => Ok(vec![]),
        Group::TransIdxSigGroups(entries) => entries
            .into_iter()
            .map(|group| {
                let (seal, sigs) = from_trans_idx_sig_group(group)?;
                Ok(Signature::Transferable(
                    SignerData::EventSeal(seal),
                    indexed_signatures(sigs)?,
                ))
            })
            .collect(),
        Group::TransLastIdxSigGroups(entries) => entries
            .into_iter()
            .map(|group| {
                let sigs = indexed_signatures(group.signatures)?;
                Ok(Signature::Transferable(
                    SignerData::LastEstablishment(group.prefix.into()),
                    sigs,
                ))
            })
            .collect(),
        _ => Err(ParseError::AttachmentError(
            "Improper attachment type".into(),
        )),
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
                    .map(|(bp, sp)| receipt_couple(bp, sp))
                    .collect();
                Group::NontransReceiptCouples(couples)
            }
        }
    }
}

impl Into<Group> for crate::event_message::signature::Signature {
    fn into(self) -> Group {
        match self {
            crate::event_message::signature::Signature::Transferable(seal, signature) => {
                let signatures: Vec<CesrIndexedSignature> =
                    signature.into_iter().map(|sig| sig.into()).collect();
                match seal {
                    crate::event_message::signature::SignerData::EventSeal(event_seal) => {
                        Group::TransIdxSigGroups(vec![trans_idx_sig_group(event_seal, signatures)])
                    }
                    crate::event_message::signature::SignerData::LastEstablishment(id) => {
                        Group::TransLastIdxSigGroups(vec![TransLastIdxSigGroup {
                            prefix: id.into(),
                            signatures,
                        }])
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
