use base64::URL_SAFE;
use nom::{bytes::complete::take, error::ErrorKind};

use crate::{error::Error, seal::EventSourceSeal};

fn attached_sn(s: &[u8]) -> nom::IResult<&[u8], u64> {
    let (more, type_c) = take(2u8)(s)?;

    const A: &'static [u8] = "0A".as_bytes();

    match type_c {
        A => {
            let (rest, parsed_sn) = take(22u8)(more)?;

            let sn =
                base64_to_num(parsed_sn).map_err(|_| nom::Err::Failure((s, ErrorKind::IsNot)))?;

            Ok((rest, sn))
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

fn base64_to_num(b64: &[u8]) -> Result<u64, Error> {
    let b64decode = base64::decode_config(b64, URL_SAFE).unwrap();
    let mut sn_array: [u8; 8] = [0; 8];
    sn_array.copy_from_slice(&b64decode[8..]);
    Ok(u64::from_be_bytes(sn_array))
}

/// extracts the Event source seal
pub fn event_source_seal(s: &[u8]) -> nom::IResult<&[u8], EventSourceSeal> {
    let (more, type_c) = take(3u8)(s)?;
    const A: &'static [u8] = "GAB".as_bytes();

    match type_c {
        A => {
            let (rest, sn) = attached_sn(more)?;
            let (rest, event_digest) = self_addressing_prefix(rest)?;
            let seal = EventSourceSeal {
                sn: u64::from(sn),
                digest: event_digest,
            };

            Ok((rest, seal))
        }
        _ => Err(nom::Err::Error((type_c, ErrorKind::IsNot))),
    }
}

#[test]
fn test_seal_parse() {
    use keri::prefix::SelfAddressingPrefix;
    let seal_attachement =
        r#"GAB0AAAAAAAAAAAAAAAAAAAAABwEOWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0"#;
    let seal = event_source_seal(seal_attachement.as_bytes()).unwrap().1;
    assert_eq!(seal.sn, 7);
    let ev_digest: SelfAddressingPrefix = "EOWdT7a7fZwRz0jiZ0DJxZEM3vsNbLDPEUk-ODnif3O0"
        .parse()
        .unwrap();
    assert_eq!(seal.digest, ev_digest);
}
