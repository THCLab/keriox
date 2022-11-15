use nom::{bytes::complete::take, error::ErrorKind, multi::count, sequence::tuple};

use super::primitives::{
    digest, identifier_signature_pair, indexed_signature, nontransferable_identifier,
    serial_number_parser, signature, timestamp_parser, transferable_quadruple,
};
use crate::event_parsing::{codes::group::GroupCode, group::Group};

pub fn group_code(s: &[u8]) -> nom::IResult<&[u8], GroupCode> {
    let (rest, payload_type) = take(4u8)(s)?;
    let group_code: GroupCode = std::str::from_utf8(payload_type)
        .map_err(|_e| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?;
    Ok((rest, group_code))
}

pub fn parse_group(stream: &[u8]) -> nom::IResult<&[u8], Group> {
    let (rest, group_code) = group_code(stream)?;
    Ok(match group_code {
        GroupCode::IndexedControllerSignatures(n) => {
            let (rest, signatures) = count(indexed_signature, n as usize)(rest)?;
            (rest, Group::IndexedControllerSignatures(signatures))
        }
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) = count(indexed_signature, n as usize)(rest)?;
            (rest, Group::IndexedWitnessSignatures(signatures))
        }
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, couple) =
                count(tuple((nontransferable_identifier, signature)), n as usize)(rest)?;
            (rest, Group::NontransferableReceiptCouples(couple))
        }
        GroupCode::SealSourceCouples(n) => {
            let (rest, couple) =
                count(tuple((serial_number_parser, digest)), n as usize)(rest).unwrap();
            (rest, Group::SourceSealCouples(couple))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, couple) =
                count(tuple((serial_number_parser, timestamp_parser)), n as usize)(rest)?;
            (rest, Group::FirstSeenReplyCouples(couple))
        }
        GroupCode::TransferableIndexedSigGroups(n) => {
            let (rest, quadruple) = count(transferable_quadruple, n as usize)(rest).unwrap();
            (rest, Group::TransferableIndexedSigGroups(quadruple))
        }
        GroupCode::LastEstSignaturesGroups(n) => {
            let (rest, couple) = count(identifier_signature_pair, n as usize)(rest)?;
            (rest, Group::LastEstSignaturesGroups(couple))
        }
        GroupCode::Frame(_) => todo!(),
        GroupCode::PathedMaterialQuadruplet(_) => todo!(),
    })
}

#[test]
pub fn test_parse_group() {
    use crate::event_parsing::primitives::Timestamp;
    let group_str = "-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-10-25T12c04c30d175309p00c00";
    let (_rest, group) = parse_group(group_str.as_bytes()).unwrap();
    let expected = (
        0,
        "2022-10-25T12:04:30.175309+00:00"
            .parse::<Timestamp>()
            .unwrap(),
    );
    assert_eq!(group, Group::FirstSeenReplyCouples(vec![expected]));
}
