#![allow(non_upper_case_globals)]
use crate::{
    event_parsing::codes::{
        basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning,
    },
    event_parsing::{
        codes::DerivationCode,
        parsing::{b64_to_num, from_text_to_bytes},
    },
    keys::PublicKey,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    sai::SelfAddressingPrefix,
};
use nom::{bytes::complete::take, error::ErrorKind};

// TODO this could be a lot nicer, but is currently written to be careful and "easy" to follow
pub fn attached_signature(s: &[u8]) -> nom::IResult<&[u8], AttachedSignaturePrefix> {
    let (more, type_c) = take(1u8)(s)?;

    const a: &[u8] = "A".as_bytes();
    const b: &[u8] = "B".as_bytes();
    const z: &[u8] = "0".as_bytes();

    match type_c {
        a => {
            let (maybe_sig, index_c) = take(1u8)(more)?;

            let index =
                b64_to_num(index_c).map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            let (rest, sig_s) = take(86u8)(maybe_sig)?;

            let sig = &from_text_to_bytes(sig_s)
                .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?[2..];

            Ok((
                rest,
                AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(sig.to_vec()), index),
            ))
        }
        b => {
            let (maybe_sig, index_c) = take(1u8)(more)?;

            let index =
                b64_to_num(index_c).map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

            let (rest, sig_s) = take(86u8)(maybe_sig)?;

            let sig = &from_text_to_bytes(sig_s)
                .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?[2..];

            Ok((
                rest,
                AttachedSignaturePrefix::new(
                    SelfSigningPrefix::ECDSAsecp256k1Sha256(sig.to_vec()),
                    index,
                ),
            ))
        }
        z => {
            let (maybe_count, type_c_2) = take(1u8)(more)?;
            match type_c_2 {
                a => {
                    let (maybe_sig, index_c) = take(2u8)(maybe_count)?;

                    let index = b64_to_num(index_c)
                        .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

                    let (rest, sig_s) = take(152u8)(maybe_sig)?;

                    let sig = base64::decode_config(sig_s, base64::URL_SAFE)
                        .map_err(|_| nom::Err::Error((index_c, ErrorKind::IsNot)))?;

                    Ok((
                        rest,
                        AttachedSignaturePrefix::new(SelfSigningPrefix::Ed448(sig), index),
                    ))
                }
                _ => Err(nom::Err::Error((type_c_2, ErrorKind::IsNot))),
            }
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

pub fn basic_prefix(s: &[u8]) -> nom::IResult<&[u8], BasicPrefix> {
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

    let (extra, b) = take(code.value_size())(rest)?;

    let decoded: Vec<_> = from_text_to_bytes(&b)
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?[code.code_size()..]
        .to_vec();
    let pk = PublicKey::new(decoded);
    Ok((extra, BasicPrefix::new(code.into(), pk)))
}

pub fn self_addressing_prefix(s: &[u8]) -> nom::IResult<&[u8], SelfAddressingPrefix> {
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

    let (extra, b) = take(code.value_size())(rest)?;

    let decoded = from_text_to_bytes(&b).map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        [code.code_size()..]
        .to_vec();

    let prefix = SelfAddressingPrefix {
        derivation: code.into(),
        digest: decoded,
    };
    Ok((extra, prefix))
}

pub fn self_signing_prefix(s: &[u8]) -> nom::IResult<&[u8], SelfSigningPrefix> {
    const EXT: &[u8] = "1".as_bytes();

    let (_, type_c) = take(1u8)(s)?;

    let (rest, code_str) = take(match type_c {
        EXT => 4u8,
        _ => 2u8,
    })(s)?;

    let code: SelfSigning = String::from_utf8(code_str.to_vec())
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        .parse()
        .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;

    let (extra, b) = take(code.value_size())(rest)?;

    let decoded = from_text_to_bytes(&b).map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?
        [code.code_size()..]
        .to_vec();

    Ok((extra, SelfSigningPrefix::new(code, decoded)))
}

pub fn attached_sn(s: &[u8]) -> nom::IResult<&[u8], u64> {
    let (more, type_c) = take(2u8)(s)?;

    const a: &[u8] = "0A".as_bytes();

    match type_c {
        a => {
            let (rest, parsed_sn) = take(22u8)(more)?;

            let sn = {
                let b64decode = from_text_to_bytes(parsed_sn)
                    .map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?[2..]
                    .to_vec();
                let mut sn_array: [u8; 8] = [0; 8];
                sn_array.copy_from_slice(&b64decode[8..]);
                u64::from_be_bytes(sn_array)
            };

            Ok((rest, sn))
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

/// extracts Identifier prefix
pub fn prefix(s: &[u8]) -> nom::IResult<&[u8], IdentifierPrefix> {
    let (rest, identifier) = match self_addressing_prefix(s) {
        Ok(sap) => Ok((sap.0, IdentifierPrefix::SelfAddressing(sap.1))),
        Err(_) => match basic_prefix(s) {
            Ok(bp) => Ok((bp.0, IdentifierPrefix::Basic(bp.1))),
            Err(e) => Err(e),
        },
    }?;
    Ok((rest, identifier))
}

#[test]
fn test() {
    assert_eq!(
        attached_signature("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("".as_bytes(), AttachedSignaturePrefix::new(SelfSigningPrefix::Ed25519Sha512(vec![0u8; 64]), 0)))
    );

    assert_eq!(
        attached_signature("BCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".as_bytes()),
        Ok(("AA".as_bytes(), AttachedSignaturePrefix::new(SelfSigningPrefix::ECDSAsecp256k1Sha256(vec![0u8; 64]), 2)))
    );
}

#[test]
fn test_basic_prefix() {
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;
    use crate::event_parsing::primitives::CesrPrimitive;

    let kp = Keypair::generate(&mut OsRng);

    let bp = BasicPrefix::Ed25519(PublicKey::new(kp.public.to_bytes().to_vec()));
    let bp_str = [&bp.to_str(), "more"].join("");
    let parsed = basic_prefix(bp_str.as_bytes()).unwrap();
    assert_eq!(parsed, ("more".as_bytes(), bp))
}

#[test]
fn test_self_adressing() {
    use crate::event_parsing::primitives::CesrPrimitive;
    let sap: SelfAddressingPrefix = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux"
        .parse()
        .unwrap();
    let str_to_parse = [&sap.to_str(), "more"].join("");
    assert_eq!(
        self_addressing_prefix(str_to_parse.as_bytes()),
        Ok(("more".as_bytes(), sap))
    );
}

#[test]
fn test_self_signing() {

    use crate::event_parsing::primitives::CesrPrimitive;
    let sig_prefix: SelfSigningPrefix =
        "0Bq1UBr1QD5TokdcnO_FmnoYsd8rB4_-oaQtk0dfFSSXPcxAu7pSaQIVfkhzckCVmTIgrdxyXS21uZgs7NxoyZAQ"
            .parse()
            .unwrap();
    let string_to_parse = [&sig_prefix.to_str(), "more"].join("");

    assert_eq!(
        self_signing_prefix(string_to_parse.as_bytes()),
        Ok(("more".as_bytes(), sig_prefix.clone()))
    );
}

#[test]
fn test_sn_parse() {
    let sn = attached_sn("0AAAAAAAAAAAAAAAAAAAAAAD".as_bytes()).unwrap();
    assert_eq!(sn, ("".as_bytes(), 3));
}
