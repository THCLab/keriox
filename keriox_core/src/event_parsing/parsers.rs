use chrono::{DateTime, FixedOffset};
use nom::{bytes::complete::take, error::ErrorKind, multi::count, sequence::tuple};

use super::codes::{
    basic::Basic, parse_value, self_addressing::SelfAddressing, self_signing::SelfSigning,
    serial_number::SerialNumberCode,
};

use super::codes::{
    attached_signature_code::AttachedSignatureCode, group::GroupCode
};
use super::primitives::{IndexedSignature, Signature, NontransferableIdentifier, Digest, Identifier, IdentifierCode, TransferableQuadruple, IdentifierSignaturesCouple};

pub fn group_code(s: &[u8]) -> nom::IResult<&[u8], GroupCode> {
    let (rest, payload_type) = take(4u8)(s)?;
    let group_code: GroupCode = std::str::from_utf8(payload_type)
        .map_err(|_e| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?;
    Ok((rest, group_code))
}

pub fn indexed_signature(s: &[u8]) -> nom::IResult<&[u8], IndexedSignature> {
    let (_more, type_c) = take(1u8)(s)?;

    const A: &[u8] = "A".as_bytes();
    const B: &[u8] = "B".as_bytes();
    const Z: &[u8] = "0".as_bytes();

    let code_len = match type_c {
        A | B => 2usize,
        Z => 4usize,
        _ => todo!(),
    };
    let (rest, code_bytes) = take(code_len)(s)?;
    let code: AttachedSignatureCode = std::str::from_utf8(code_bytes).unwrap().parse().unwrap();
    parse_value(code, rest)
}

pub fn signature(s: &[u8]) -> nom::IResult<&[u8], Signature> {
    const EXT: &[u8] = "1".as_bytes();

    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 4u8,
        _ => 2u8,
    })(s)?;

    let code: SelfSigning = std::str::from_utf8(code_str).unwrap().parse().unwrap();
    parse_value(code, rest)
}

pub fn nontransferable_identifier(s: &[u8]) -> nom::IResult<&[u8], NontransferableIdentifier> {
    const EXT: &[u8] = "1".as_bytes();

    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 4u8,
        _ => 1u8,
    })(s)?;

    let code: Basic = String::from_utf8(code_str.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;
    parse_value(code, rest)
}

pub fn digest(s: &[u8]) -> nom::IResult<&[u8], Digest> {
    const EXT: &[u8] = "0".as_bytes();
    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 2u8,
        _ => 1u8,
    })(s)?;

    let code: SelfAddressing = String::from_utf8(code_str.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;
    parse_value(code, rest)
}

pub fn identifier(s: &[u8]) -> nom::IResult<&[u8], Identifier> {
    let (rest, identifier) = match digest(s) {
        Ok(sap) => Ok((sap.0, (IdentifierCode::SelfAddressing(sap.1 .0), sap.1 .1))),
        Err(_) => match nontransferable_identifier(s) {
            Ok(bp) => Ok((bp.0, (IdentifierCode::Basic(bp.1 .0), bp.1 .1))),
            Err(e) => Err(e),
        },
    }?;
    Ok((rest, identifier))
}

pub fn serial_number_parser(s: &[u8]) -> nom::IResult<&[u8], u64> {
    let (rest, type_c) = take(2u8)(s)?;

    let code: SerialNumberCode = String::from_utf8(type_c.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;

    let (rest, value) = parse_value(code, rest)?;

    let sn = {
        let mut sn_array: [u8; 8] = [0; 8];
        sn_array.copy_from_slice(&value.1[8..]);
        u64::from_be_bytes(sn_array)
    };

    Ok((rest, sn))
}

// TODO add and use codes for Timestamp
pub fn timestamp(s: &[u8]) -> nom::IResult<&[u8], DateTime<FixedOffset>> {
    let (more, type_c) = take(4u8)(s)?;

    match type_c {
        b"1AAG" => {
            let (rest, parsed_timestamp) = take(32u8)(more)?;

            let timestamp = {
                let dt_str = String::from_utf8(parsed_timestamp.to_vec())
                    .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?
                    .replace('c', ":")
                    .replace('d', ".")
                    .replace('p', "+");
                dt_str
                    .parse::<DateTime<FixedOffset>>()
                    .map_err(|_e| nom::Err::Error((s, ErrorKind::IsNot)))?
            };

            Ok((rest, timestamp))
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

pub fn transferable_quadruple(s: &[u8]) -> nom::IResult<&[u8], TransferableQuadruple> {
    let (rest, (identifier, serial_number, digest)) =
        tuple((identifier, serial_number_parser, digest))(s)?;
    let (rest, GroupCode::IndexedControllerSignatures(signatures_cout)) = group_code(rest)? else {
		todo!()
	};
    let (rest, signatures) = count(indexed_signature, signatures_cout as usize)(rest)?;
    Ok((rest, (identifier, serial_number, digest, signatures)))
}

pub fn identifier_signature_pair(s: &[u8]) -> nom::IResult<&[u8], IdentifierSignaturesCouple> {
    let (rest, identifier) = identifier(s)?;
    let (rest, GroupCode::IndexedControllerSignatures(signatures_cout)) = group_code(rest)? else {
		todo!()
	};
    let (rest, signatures) = count(indexed_signature, signatures_cout as usize)(rest)?;
    Ok((rest, (identifier, signatures)))
}

#[test]
fn test_indexed_signature() {
    assert_eq!(
        indexed_signature("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), (AttachedSignatureCode { index: 0, code: SelfSigning::Ed25519Sha512 }, vec![0u8; 64])))
    );

    assert_eq!(
        indexed_signature("BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("AA".as_bytes(), (AttachedSignatureCode { index: 2, code: SelfSigning::ECDSAsecp256k1Sha256 }, vec![0u8; 64])))
    );
}

#[test]
fn test_basic_identifier() {
    let pk_raw = vec![
        249, 247, 209, 34, 220, 90, 114, 42, 247, 149, 69, 221, 219, 244, 123, 60, 41, 37, 217,
        217, 199, 132, 199, 134, 143, 65, 11, 79, 135, 11, 85, 16,
    ];
    let str_to_parse = "DPn30SLcWnIq95VF3dv0ezwpJdnZx4THho9BC0-HC1UQmore";

    let parsed = nontransferable_identifier(str_to_parse.as_bytes()).unwrap();
    assert_eq!(parsed, ("more".as_bytes(), (Basic::Ed25519, pk_raw)))
}

#[test]
fn test_digest() {
    let digest_raw = vec![
        176, 185, 47, 120, 129, 84, 62, 251, 119, 243, 24, 109, 129, 134, 9, 68, 32, 169, 0, 99,
        187, 90, 56, 199, 85, 29, 251, 61, 172, 47, 235, 177,
    ];
    let sai_str = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
    let str_to_parse = [&sai_str, "more"].join("");
    assert_eq!(
        digest(str_to_parse.as_bytes()),
        Ok(("more".as_bytes(), (SelfAddressing::Blake3_256, digest_raw)))
    );
}

#[test]
fn test_signature() {
    let signature_string =
        "0Bq1UBr1QD5TokdcnO_FmnoYsd8rB4_-oaQtk0dfFSSXPcxAu7pSaQIVfkhzckCVmTIgrdxyXS21uZgs7NxoyZAQ";
    let string_to_parse = [&signature_string, "more"].join("");

    let signature_raw = vec![
        181, 80, 26, 245, 64, 62, 83, 162, 71, 92, 156, 239, 197, 154, 122, 24, 177, 223, 43, 7,
        143, 254, 161, 164, 45, 147, 71, 95, 21, 36, 151, 61, 204, 64, 187, 186, 82, 105, 2, 21,
        126, 72, 115, 114, 64, 149, 153, 50, 32, 173, 220, 114, 93, 45, 181, 185, 152, 44, 236,
        220, 104, 201, 144, 16,
    ];

    assert_eq!(
        signature(string_to_parse.as_bytes()),
        Ok((
            "more".as_bytes(),
            (SelfSigning::Ed25519Sha512, signature_raw)
        ))
    );
}

#[test]
fn test_sn_parse() {
    let sn = serial_number_parser("0AAAAAAAAAAAAAAAAAAAAAAD".as_bytes()).unwrap();
    assert_eq!(sn, ("".as_bytes(), 3));
}
