use nom::{
    bytes::complete::take,
    error::ErrorKind,
    multi::{count, many0},
    sequence::tuple,
    Needed,
};

use super::primitives::{
    digest, identifier_signature_pair, indexed_signature, material_path,
    nontransferable_identifier, serial_number_parser, signature, timestamp_parser,
    transferable_quadruple,
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
        GroupCode::Frame(n) => {
            // n * 4 is all attachments length
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    let (extra, atts) = many0(parse_group)(total)?;
                    if !extra.is_empty() {
                        // something is wrong, should not happend
                        Err(nom::Err::Incomplete(Needed::Size(
                            (n * 4) as usize - rest.len(),
                        )))
                    } else {
                        Ok((rest, Group::Frame(atts)))
                    }
                }
                Err(nom::Err::Error((rest, _))) => Err(nom::Err::Incomplete(Needed::Size(
                    (n * 4) as usize - rest.len(),
                ))),
                Err(e) => Err(e),
            }?
        }
        GroupCode::PathedMaterialQuadruple(n) => {
            // n * 4 is all path and attachments length (?)
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    let (extra, mp) = material_path(total)?;
                    let (_extra, attachment) = many0(parse_group)(extra)?;

                    Ok((rest, Group::PathedMaterialQuadruplet(mp, attachment)))
                }
                Err(e) => Err(e),
            }?
        }
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

#[test]
fn test_pathed_material() {
    use crate::event_parsing::path::MaterialPath;

    let attached_str = "-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
    let (_rest, attached_material) = parse_group(attached_str.as_bytes()).unwrap();
    let expected_path = MaterialPath::to_path("-a".into());
    if let Group::PathedMaterialQuadruplet(material_path, groups) = attached_material {
        assert_eq!(material_path, expected_path);
        assert_eq!(groups.len(), 1)
    };
}
