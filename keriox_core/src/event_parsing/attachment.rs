use std::convert::TryFrom;

use nom::{
    bytes::complete::take,
    error::ErrorKind,
    multi::{count, many0},
    Needed,
};

use crate::{
    event::sections::seal::{EventSeal, SourceSeal},
    event_message::signature::Signature,
    prefix::AttachedSignaturePrefix,
};

use super::{
    codes::{group::GroupCode, material_path_codes::MaterialPathCode},
    parsers::primitives::timestamp_parser,
    path::MaterialPath,
    prefix::{
        attached_signature, attached_sn, basic_prefix, prefix, self_addressing_prefix,
        self_signing_prefix,
    },
    Attachment,
};

fn event_seal(s: &[u8]) -> nom::IResult<&[u8], EventSeal> {
    let (rest, identifier) = prefix(s)?;

    let (rest, sn) = attached_sn(rest)?;
    let (rest, event_digest) = self_addressing_prefix(rest)?;
    let seal = EventSeal {
        prefix: identifier,
        sn,
        event_digest,
    };

    Ok((rest, seal))
}

fn indexed_signatures(input: &[u8]) -> nom::IResult<&[u8], Vec<AttachedSignaturePrefix>> {
    attachment(input).map(|(rest, att)| match att {
        Attachment::AttachedSignatures(sigs) => Ok((rest, sigs)),
        _ => Err(nom::Err::Error((rest, ErrorKind::IsNot))),
    })?
}

pub fn material_path(s: &[u8]) -> nom::IResult<&[u8], MaterialPath> {
    let (more, type_c) = take(4u8)(s)?;

    let payload_type: MaterialPathCode = std::str::from_utf8(type_c).unwrap().parse().unwrap();
    // parse amount of quadruplets
    let full_size = payload_type.size() * 4;
    // parse full path
    let (more, base) = take(full_size)(more)?;

    let path = MaterialPath::new(
        payload_type,
        String::from_utf8(base.to_vec()).unwrap_or_default(),
    );

    Ok((more, path))
}

pub fn attachment(s: &[u8]) -> nom::IResult<&[u8], Attachment> {
    let (rest, payload_type) = take(4u8)(s)?;
    let group_code: GroupCode = std::str::from_utf8(payload_type)
        .map_err(|_e| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?;
    // Can't parse payload type
    match group_code {
        GroupCode::IndexedControllerSignatures(n) => {
            let (rest, signatures) = count(attached_signature, n as usize)(rest)?;
            Ok((rest, Attachment::AttachedSignatures(signatures)))
        }
        GroupCode::IndexedWitnessSignatures(n) => {
            let (rest, signatures) = count(attached_signature, n as usize)(rest)?;
            Ok((rest, Attachment::AttachedWitnessSignatures(signatures)))
        }
        GroupCode::NontransferableReceiptCouples(n) => {
            let (rest, receipts) = count(
                nom::sequence::tuple((basic_prefix, self_signing_prefix)),
                n as usize,
            )(rest)?;
            Ok((rest, Attachment::ReceiptCouplets(receipts)))
        }
        GroupCode::SealSourceCouples(n) => {
            let (rest, quadruple) = count(
                nom::sequence::tuple((attached_sn, self_addressing_prefix)),
                n as usize,
            )(rest)?;
            let source_seals = quadruple
                .into_iter()
                .map(|(sn, digest)| SourceSeal::new(sn, digest))
                .collect();
            Ok((rest, Attachment::SealSourceCouplets(source_seals)))
        }
        GroupCode::FirstSeenReplyCouples(n) => {
            let (rest, first_seen_replys) = count(
                nom::sequence::tuple((attached_sn, timestamp_parser)),
                n as usize,
            )(rest)?;
            Ok((rest, Attachment::FirstSeenReply(first_seen_replys)))
        }
        GroupCode::TransferableIndexedSigGroups(n) => {
            let (rest, signatures) = count(
                nom::sequence::tuple((event_seal, indexed_signatures)),
                n as usize,
            )(rest)?;
            Ok((rest, Attachment::SealSignaturesGroups(signatures)))
        }
        GroupCode::LastEstSignaturesGroups(n) => {
            let (rest, last_established_signature) = count(
                nom::sequence::tuple((prefix, indexed_signatures)),
                n as usize,
            )(rest)?;
            Ok((
                rest,
                Attachment::LastEstSignaturesGroups(last_established_signature),
            ))
        }
        GroupCode::Frame(n) => {
            // sc * 4 is all attachments length
            match nom::bytes::complete::take(n * 4)(rest) {
                Ok((rest, total)) => {
                    let (extra, atts) = many0(attachment)(total)?;
                    if !extra.is_empty() {
                        // something is wrong, should not happend
                        Err(nom::Err::Incomplete(Needed::Size(
                            (n * 4) as usize - rest.len(),
                        )))
                    } else {
                        Ok((rest, Attachment::Frame(atts)))
                    }
                }
                Err(nom::Err::Error((rest, _))) => Err(nom::Err::Incomplete(Needed::Size(
                    (n * 4) as usize - rest.len(),
                ))),
                Err(e) => Err(e),
            }
        }
        GroupCode::PathedMaterialQuadruplet(n) => match nom::bytes::complete::take(n * 4)(rest) {
            Ok((rest, total)) => {
                let (extra, mp) = material_path(total)?;
                let (_extra, attachment) = many0(attachment)(extra)?;
                let sigs = attachment
                    .into_iter()
                    .map(|att| Vec::<Signature>::try_from(att).unwrap())
                    .flatten()
                    .collect();

                Ok((rest, Attachment::PathedMaterialQuadruplet(mp, sigs)))
            }
            Err(e) => Err(e),
        },
    }
}

#[test]
fn test_sigs() {
    use crate::prefix::{AttachedSignaturePrefix, SelfSigningPrefix};

    assert_eq!(
        attachment("-AABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), Attachment::AttachedSignatures(vec![AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]), 0)])))
    );

    assert!(attachment("-AABAA0Q7bqPvenjWXo_YIikMBKOg-pghLKwBi1Plm0PEqdv67L1_c6dq9bll7OFnoLp0a74Nw1cBGdjIPcu-yAllHAw".as_bytes()).is_ok());

    assert_eq!(
        attachment("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAextra data".as_bytes()),
        Ok(("extra data".as_bytes(), Attachment::AttachedSignatures(vec![
            AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512( vec![0u8; 64]), 0),
            AttachedSignaturePrefix::new(SelfSigningPrefix::Ed448(vec![0u8; 114]), 2)
        ])))
    );

    assert_eq!(
        attachment("-AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0AACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), Attachment::AttachedSignatures(vec![
            AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]), 0),
            AttachedSignaturePrefix::new(SelfSigningPrefix::Ed448(vec![0u8; 114]), 2)
        ])))
    )
}

#[test]
fn test_attachement() {
    let attached_str = "-GAC0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS0AAAAAAAAAAAAAAAAAAAAAABEJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS";
    let (_rest, attached_sn_dig) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(
        attached_sn_dig,
        Attachment::SealSourceCouplets(vec![
            SourceSeal {
                sn: 1,
                digest: "EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS"
                    .parse()
                    .unwrap()
            },
            SourceSeal {
                sn: 1,
                digest: "EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS"
                    .parse()
                    .unwrap()
            }
        ])
    );

    let attached_str = "-FABEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o0AAAAAAAAAAAAAAAAAAAAAAAEKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o-AABAABB5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWtzshh2HGCL_H_j4i1b9kF";
    let (_rest, seal) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(
        seal,
        Attachment::SealSignaturesGroups(vec![
            (
                EventSeal {
                    prefix: "EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o"
                        .parse()
                        .unwrap(),
                    sn: 0,
                    event_digest: "EKC8085pwSwzLwUGzh-HrEoFDwZnCJq27bVp5atdMT9o"
                        .parse()
                        .unwrap()
                },
                vec!["AABB5IVZOhEfcH4TBQgOCyMgyQrJujtBBjT8K_zTPk0-FLMtTZuBgXV7jnLw6fDe6FWtzshh2HGCL_H_j4i1b9kF".parse().unwrap()]
        )
        ])
    );

    let attached_str = "-CABBMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y0BB6cL0DtDVDW26lgjbQu0_D_Pd_6ovBZj6fU-Qjmm7epVs51jEOOwXKbmG4yUvCSN-DQSYSc7HXZRp8CfAw9DQL";
    let (_rest, seal) = attachment(attached_str.as_bytes()).unwrap();
    assert_eq!(seal, Attachment::ReceiptCouplets(
        vec![
            ("BMrwi0a-Zblpqe5Hg7w7iz9JCKnMgWKu_W9w4aNUL64y".parse().unwrap(), "0BB6cL0DtDVDW26lgjbQu0_D_Pd_6ovBZj6fU-Qjmm7epVs51jEOOwXKbmG4yUvCSN-DQSYSc7HXZRp8CfAw9DQL".parse().unwrap())
            ]
        )
    );

    let cesr_attachment = "-AABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
    let (_rest, att) = attachment(cesr_attachment.as_bytes()).unwrap();
    assert_eq!(att, Attachment::AttachedSignatures(
        vec!["AAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ".parse().unwrap()]
    ));

    let cesr_attachment = "-VAj-HABEIaGMMWJFPmtXznY1IIiKDIrg-vIyge6mBl2QV8dDjI3-AABAAB6P97kZ3al3V3z3VstRtHRPeOrotuqZZUgBl2yHzgpGyOjAXYGinVqWLAMhdmQ089FTSAzqSTBmJzI8RvIezsJ";
    let (rest, att) = attachment(cesr_attachment.as_bytes()).unwrap();
    assert!(matches!(att, Attachment::Frame(_)));
    assert!(rest.is_empty());
}

#[test]
fn test_pathed_material() {
    let attached_str = "-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA";
    let (_rest, attached_material) = attachment(attached_str.as_bytes()).unwrap();
    assert!(matches!(
        attached_material,
        Attachment::PathedMaterialQuadruplet(_, _)
    ));
}

#[test]
fn test_path() {
    let attached_str = "6AABAAA-";
    let (_rest, attached_material) = material_path(attached_str.as_bytes()).unwrap();
    assert_eq!(attached_material, MaterialPath::to_path("-".into()));
}
