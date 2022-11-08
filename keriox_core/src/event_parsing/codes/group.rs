use std::str::FromStr;

use crate::event_parsing::{
    error::Error,
    parsing::{adjust_with_num, b64_to_num},
};

use super::DerivationCode;

#[derive(Debug, PartialEq, Eq)]
pub enum GroupCode {
    IndexedControllerSignatures(u16),
    IndexedWitnessSignatures(u16),
    NontransferableReceiptCouples(u16),
    TransferableReceiptQuadruples(u16),
    FirstSeenReplyCouples(u16),
    TransferableIndexedSigGroups(u16),
    LastEstSignaturesGroups(u16),
    Frame(u16),
    // it's from cesr-proof
    PathedMaterialQuadruplet(u16),
}

impl DerivationCode for GroupCode {
    fn value_size(&self) -> usize {
        0
    }

    fn soft_size(&self) -> usize {
        2
    }

    fn hard_size(&self) -> usize {
        2
    }

    fn to_str(&self) -> String {
        let (code, count) = match self {
            GroupCode::IndexedControllerSignatures(count) => ("-A", count),
            GroupCode::IndexedWitnessSignatures(count) => ("-B", count),
            GroupCode::NontransferableReceiptCouples(count) => ("-C", count),
            GroupCode::FirstSeenReplyCouples(count) => ("-E", count),
            GroupCode::TransferableIndexedSigGroups(count) => ("-F", count),
            GroupCode::TransferableReceiptQuadruples(count) => ("-G", count),
            GroupCode::LastEstSignaturesGroups(count) => ("-H", count),
            GroupCode::Frame(len) => ("-V", len),
            GroupCode::PathedMaterialQuadruplet(len) => ("-L", len),
        };
        [code, &adjust_with_num(count.to_owned(), self.soft_size())].join("")
    }
}

impl FromStr for GroupCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..2).ok_or_else(|| Error::EmptyCodeError)?;
        let count_part = s.get(2..4).ok_or_else(|| Error::EmptyCodeError)?;
        let count = b64_to_num(count_part.as_bytes())?;
        match code {
            "-A" => Ok(Self::IndexedControllerSignatures(count)),
            "-B" => Ok(Self::IndexedWitnessSignatures(count)),
            "-C" => Ok(Self::NontransferableReceiptCouples(count)),
            "-D" => todo!(),
            "-E" => Ok(Self::FirstSeenReplyCouples(count)),
            "-F" => Ok(Self::TransferableIndexedSigGroups(count)),
            // todo why not in cesr docs?
            "-H" => Ok(Self::LastEstSignaturesGroups(count)),
            // todo why not in cesr docs?
            "-G" => Ok(Self::TransferableReceiptQuadruples(count)),
            // todo why not in cesr-proof docs?
            "-L" => Ok(Self::PathedMaterialQuadruplet(count)),
            "-U" => todo!(),
            "-V" => Ok(Self::Frame(count)),
            "-W" => todo!(),
            "-X" => todo!(),
            "-Y" => todo!(),
            "-Z" => todo!(),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[test]
pub fn test_group_codes_to_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3).to_str(), "-AAD");
    assert_eq!(GroupCode::IndexedWitnessSignatures(30).to_str(), "-BAe");
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100).to_str(),
        "-CBk"
    );
    assert_eq!(GroupCode::FirstSeenReplyCouples(127).to_str(), "-EB_");
    assert_eq!(
        GroupCode::TransferableIndexedSigGroups(4095).to_str(),
        "-F__"
    );
    assert_eq!(GroupCode::TransferableReceiptQuadruples(0).to_str(), "-GAA");
    assert_eq!(GroupCode::Frame(1000).to_str(), "-VPo");
    Ok(())
}

#[test]
pub fn test_group_codes_from_str() -> Result<(), Error> {
    assert_eq!(GroupCode::IndexedControllerSignatures(3), "-AAD".parse()?);
    assert_eq!(GroupCode::IndexedWitnessSignatures(30), "-BAe".parse()?);
    assert_eq!(
        GroupCode::NontransferableReceiptCouples(100),
        "-CBk".parse()?
    );
    assert_eq!(GroupCode::FirstSeenReplyCouples(127), "-EB_".parse()?);
    assert_eq!(
        GroupCode::TransferableIndexedSigGroups(4095),
        "-F__".parse()?
    );
    assert_eq!(GroupCode::TransferableReceiptQuadruples(0), "-GAA".parse()?);
    assert_eq!(GroupCode::Frame(1000), "-VPo".parse()?);
    Ok(())
}
