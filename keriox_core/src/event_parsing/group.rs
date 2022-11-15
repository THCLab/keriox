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
    FirstSeenReplyCouples(Vec<(u64, Timestamp)>),
    TransferableIndexedSigGroups(Vec<TransferableQuadruple>),
    LastEstSignaturesGroups(Vec<IdentifierSignaturesCouple>),
    Frame(Vec<Group>),
    // it's from cesr-proof
    PathedMaterialQuadruplet(u16),
}

impl Group {
    pub fn to_cesr_str(&self) -> String {
        let (code, value) = match self {
            Group::IndexedControllerSignatures(sigs) => (
                GroupCode::IndexedControllerSignatures(sigs.len() as u16),
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join("")),
            ),
            Group::IndexedWitnessSignatures(sigs) => (
                GroupCode::IndexedWitnessSignatures(sigs.len() as u16),
                sigs.iter()
                    .fold("".into(), |acc, s| [acc, s.to_str()].join("")),
            ),
            Group::NontransferableReceiptCouples(couples) => (
                GroupCode::NontransferableReceiptCouples(couples.len() as u16),
                couples
                    .iter()
                    .fold("".into(), |acc, (identifeir, signature)| {
                        [acc, identifeir.to_str(), signature.to_str()].join("")
                    }),
            ),
            Group::SourceSealCouples(quadruple) => (
                GroupCode::SealSourceCouples(quadruple.len() as u16),
                quadruple.into_iter().fold("".into(), |acc, (sn, digest)| {
                    [acc, "0A".to_string(), pack_sn(*sn), digest.to_str()].join("")
                }),
            ),
            Group::FirstSeenReplyCouples(couples) => (
                GroupCode::FirstSeenReplyCouples(couples.len() as u16),
                couples.iter().fold("".into(), |acc, (sn, dt)| {
                    [acc, "0A".to_string(), pack_sn(*sn), pack_datetime(dt)].join("")
                }),
            ),
            Group::TransferableIndexedSigGroups(groups) => (
                GroupCode::TransferableIndexedSigGroups(groups.len() as u16),
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
                    }),
            ),
            Group::LastEstSignaturesGroups(couples) => (
                GroupCode::LastEstSignaturesGroups(couples.len() as u16),
                couples
                    .iter()
                    .fold("".into(), |acc, (identifier, signatures)| {
                        let signatures = signatures
                            .iter()
                            .fold("".into(), |acc, s| [acc, s.to_str()].join(""));
                        [acc, identifier.to_str(), signatures].join("")
                    }),
            ),
            Group::Frame(att) => {
                let data = att
                    .iter()
                    .fold("".to_string(), |acc, att| [acc, att.to_cesr_str()].concat());
                let code = GroupCode::Frame(data.len() as u16);
                (code, data)
            }
            Group::PathedMaterialQuadruplet(_) => todo!(),
        };
        [code.to_str(), value].concat()
    }
}
