use super::{
    codes::{group::GroupCode, serial_number::pack_sn, timestamp::pack_datetime, DerivationCode},
    primitives::{
        CesrPrimitive, Digest, IdentifierSignaturesCouple, IndexedSignature, PublicKey, Signature,
        Timestamp, TransferableQuadruple,
    },
};

#[derive(Clone, Debug, PartialEq)]
pub enum Group {
    IndexedControllerSignatures(Vec<IndexedSignature>),
    IndexedWitnessSignatures(Vec<IndexedSignature>),
    NontransferableReceiptCouples(Vec<(PublicKey, Signature)>),
    SourceSealCouples(Vec<(u64, Digest)>),
    // todo add timestamp
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    TransferableIndexedSigGroups(Vec<TransferableQuadruple>),
    LastEstSignaturesGroups(Vec<IdentifierSignaturesCouple>),

    // todo
    Frame(u16),
    // it's from cesr-proof
    PathedMaterialQuadruplet(u16),
}

impl Group {
    pub fn to_cesr_str(&self) -> String {
        [self.code(), self.data_to_str()].join("")
    }
    fn data_to_str(&self) -> String {
        match self {
            Group::IndexedControllerSignatures(sigs) | Group::IndexedWitnessSignatures(sigs) => {
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join(""))
            }
            Group::NontransferableReceiptCouples(couples) => {
                couples
                    .iter()
                    .fold("".into(), |acc, (identifeir, signature)| {
                        [acc, identifeir.to_str(), signature.to_str()].join("")
                    })
            }
            Group::SourceSealCouples(quadruple) => {
                quadruple.into_iter().fold("".into(), |acc, (sn, digest)| {
                    // let signatures = signatures.iter().fold("".into(), |acc, s| {
                    //     [acc, s.to_str()].join("")
                    // });
                    [acc, "0A".to_string(), pack_sn(*sn), digest.to_str()].join("")
                })
            }
            Group::FirstSeenReplyCouples(couples) => {
                couples.iter().fold("".into(), |acc, (sn, dt)| {
                    [acc, "0A".to_string(), pack_sn(*sn), pack_datetime(dt)].join("")
                })
            }
            Group::TransferableIndexedSigGroups(groups) => {
                groups
                    .iter()
                    .fold("".into(), |acc, (identifier, sn, digest, signatures)| {
                        let signatures = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [
                            acc,
                            identifier.to_str(),
                            "0A".to_string(),
                            pack_sn(*sn),
                            digest.to_str(),
                            signatures,
                        ]
                        .join("")
                    })
            }
            Group::LastEstSignaturesGroups(couples) => {
                couples
                    .iter()
                    .fold("".into(), |acc, (identifier, signatures)| {
                        let signatures = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [acc, identifier.to_str(), signatures].join("")
                    })
            }
            Group::Frame(_) => todo!(),
            Group::PathedMaterialQuadruplet(_) => todo!(),
        }
    }

    fn code(&self) -> String {
        match self {
            Group::IndexedControllerSignatures(sigs) => {
                GroupCode::IndexedControllerSignatures(sigs.len() as u16)
            }
            Group::IndexedWitnessSignatures(sigs) => {
                GroupCode::IndexedWitnessSignatures(sigs.len() as u16)
            }
            Group::NontransferableReceiptCouples(couples) => {
                GroupCode::NontransferableReceiptCouples(couples.len() as u16)
            }
            Group::SourceSealCouples(couple) => GroupCode::SealSourceCouples(couple.len() as u16),
            Group::FirstSeenReplyCouples(couple) => {
                GroupCode::FirstSeenReplyCouples(couple.len() as u16)
            }
            Group::TransferableIndexedSigGroups(group) => {
                GroupCode::TransferableIndexedSigGroups(group.len() as u16)
            }
            Group::LastEstSignaturesGroups(group) => {
                GroupCode::LastEstSignaturesGroups(group.len() as u16)
            }
            Group::Frame(_) => todo!(),
            Group::PathedMaterialQuadruplet(_) => todo!(),
        }
        .to_str()
    }
}
