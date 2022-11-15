use std::str::FromStr;

use crate::event_parsing::parsers::{group::parse_group, parse_primitive};

use super::{
    codes::{group::GroupCode, Group, PrimitiveCode},
    error::Error,
};

#[derive(PartialEq, Debug)]
pub enum Value {
    Primitive(PrimitiveCode, Vec<u8>),
    Group(GroupCode, Group),
}

pub fn parse_value(stream: &[u8]) -> nom::IResult<&[u8], Value> {
    const GROUP_SELECTOR: &[u8] = "-".as_bytes();
    match stream
        .get(..1)
        .ok_or_else(|| Error::EmptyCodeError)
        .unwrap()
    {
        GROUP_SELECTOR => {
            let code = GroupCode::from_str(std::str::from_utf8(stream).unwrap()).unwrap();
            let (rest, group) = parse_group(stream)?;
            Ok((rest, Value::Group(code, group)))
        }
        _ => {
            let code = PrimitiveCode::from_str(std::str::from_utf8(stream).unwrap()).unwrap();
            let (rest, value) = parse_primitive(code, stream)?;
            Ok((rest, Value::Primitive(value.0, value.1)))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::event_parsing::{
        codes::{
            attached_signature_code::AttachedSignatureCode, basic::Basic, group::GroupCode,
            self_addressing::SelfAddressing, self_signing::SelfSigning, Group,
        },
        primitives::IdentifierCode,
        value::{parse_value, Value},
    };

    #[test]
    fn test_parse_controller_signatures() {
        let val = parse_value("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
        let expected_val = Value::Group(
            GroupCode::IndexedControllerSignatures(1),
            Group::IndexedControllerSignatures(vec![(
                AttachedSignatureCode {
                    index: 0,
                    code: SelfSigning::Ed25519Sha512,
                },
                vec![0u8; 64],
            )]),
        );
        assert_eq!(val, Ok(("".as_bytes(), expected_val)));

        let val = parse_value("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes());
        let expected_val = Value::Group(
            GroupCode::IndexedControllerSignatures(2),
            Group::IndexedControllerSignatures(vec![
                (
                    AttachedSignatureCode {
                        index: 0,
                        code: SelfSigning::Ed25519Sha512,
                    },
                    vec![0u8; 64],
                ),
                (
                    AttachedSignatureCode {
                        index: 2,
                        code: SelfSigning::Ed448,
                    },
                    vec![0u8; 114],
                ),
            ]),
        );
        assert_eq!(val, Ok(("".as_bytes(), expected_val)));

        let val = parse_value("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data".as_bytes());
        let expected_val = Value::Group(
            GroupCode::IndexedControllerSignatures(2),
            Group::IndexedControllerSignatures(vec![
                (
                    AttachedSignatureCode {
                        index: 0,
                        code: SelfSigning::Ed25519Sha512,
                    },
                    vec![0u8; 64],
                ),
                (
                    AttachedSignatureCode {
                        index: 2,
                        code: SelfSigning::Ed448,
                    },
                    vec![0u8; 114],
                ),
            ]),
        );
        assert_eq!(val, Ok(("extra data".as_bytes(), expected_val)));

        assert!(parse_value("-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw".as_bytes()).is_ok());
    }

    #[test]
    fn test_parse_groups() {
        let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS";
        let (_rest, attached_sn_dig) = parse_value(attached_str.as_bytes()).unwrap();
        let expected_value = Value::Group(
            GroupCode::SealSourceCouples(2),
            Group::SourceSealCouples(vec![
                (
                    1,
                    (
                        SelfAddressing::Blake3_256,
                        vec![
                            155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100,
                            130, 155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11,
                            18,
                        ],
                    ),
                ),
                (
                    1,
                    (
                        SelfAddressing::Blake3_256,
                        vec![
                            155, 80, 157, 217, 47, 194, 115, 41, 84, 97, 57, 161, 85, 91, 45, 100,
                            130, 155, 232, 203, 190, 33, 176, 212, 3, 142, 147, 48, 111, 55, 11,
                            18,
                        ],
                    ),
                ),
            ]),
        );
        assert_eq!(attached_sn_dig, expected_value);

        let attached_str = "-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAABB5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWtzshh2HGCL_H_j4i1b9kF";
        let (_rest, value) = parse_value(attached_str.as_bytes()).unwrap();
        let expected_value = Value::Group(
            GroupCode::TransferableIndexedSigGroups(1),
            Group::TransferableIndexedSigGroups(vec![(
                (
                    IdentifierCode::SelfAddressing(SelfAddressing::Blake3_256),
                    vec![
                        160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5,
                        15, 6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
                    ],
                ),
                0,
                (
                    SelfAddressing::Blake3_256,
                    vec![
                        160, 188, 211, 206, 105, 193, 44, 51, 47, 5, 6, 206, 31, 135, 172, 74, 5,
                        15, 6, 103, 8, 154, 182, 237, 181, 105, 229, 171, 93, 49, 63, 104,
                    ],
                ),
                vec![(
                    AttachedSignatureCode {
                        index: 0,
                        code: SelfSigning::Ed25519Sha512,
                    },
                    vec![
                        65, 228, 133, 89, 58, 17, 31, 112, 126, 19, 5, 8, 14, 11, 35, 32, 201, 10,
                        201, 186, 59, 65, 6, 52, 252, 43, 252, 211, 62, 77, 62, 20, 179, 45, 77,
                        155, 129, 129, 117, 123, 142, 114, 240, 233, 240, 222, 232, 85, 173, 206,
                        200, 97, 216, 113, 130, 47, 241, 255, 143, 136, 181, 111, 217, 5,
                    ],
                )],
            )]),
        );

        assert_eq!(value, expected_value);

        let attached_str = "-CABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BB6cL0DtDVDW26lgjbQu0_D_Pd_6ovBZj6fU-Qjmm7epVs51jEOOwXKbmG4yUvCSN-DQSYSc7HXZRp8CfAw9DQL";
        let (_rest, value) = parse_value(attached_str.as_bytes()).unwrap();
        let expected_value = Value::Group(
            GroupCode::NontransferableReceiptCouples(1),
            Group::NontransferableReceiptCouples(vec![(
                (
                    Basic::Ed25519NT,
                    vec![
                        202, 240, 139, 70, 190, 101, 185, 105, 169, 238, 71, 131, 188, 59, 139, 63,
                        73, 8, 169, 204, 129, 98, 174, 253, 111, 112, 225, 163, 84, 47, 174, 50,
                    ],
                ),
                (
                    SelfSigning::Ed25519Sha512,
                    vec![
                        122, 112, 189, 3, 180, 53, 67, 91, 110, 165, 130, 54, 208, 187, 79, 195,
                        252, 247, 127, 234, 139, 193, 102, 62, 159, 83, 228, 35, 154, 110, 222,
                        165, 91, 57, 214, 49, 14, 59, 5, 202, 110, 97, 184, 201, 75, 194, 72, 223,
                        131, 65, 38, 18, 115, 177, 215, 101, 26, 124, 9, 240, 48, 244, 52, 11,
                    ],
                ),
            )]),
        );

        assert_eq!(value, expected_value);

        let cesr_attachment = "-AABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
        let (_rest, value) = parse_value(cesr_attachment.as_bytes()).unwrap();
        let expected_value = Value::Group(
            GroupCode::IndexedControllerSignatures(1),
            Group::IndexedControllerSignatures(vec![(
                AttachedSignatureCode {
                    index: 0,
                    code: SelfSigning::Ed25519Sha512,
                },
                vec![
                    122, 63, 222, 228, 103, 118, 165, 221, 93, 243, 221, 91, 45, 70, 209, 209, 61,
                    227, 171, 162, 219, 170, 101, 149, 32, 6, 93, 178, 31, 56, 41, 27, 35, 163, 1,
                    118, 6, 138, 117, 106, 88, 176, 12, 133, 217, 144, 211, 207, 69, 77, 32, 51,
                    169, 36, 193, 152, 156, 200, 241, 27, 200, 123, 59, 9,
                ],
            )]),
        );

        assert_eq!(value, expected_value);

        // TODO
        // let cesr_attachment = "-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
        // let (rest, att) = attachment(cesr_attachment.as_bytes()).unwrap();
        // assert!(matches!(att, Attachment::Frame(_)));
        // assert!(rest.is_empty());
    }
}
