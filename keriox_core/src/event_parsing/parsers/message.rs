use std::io::Cursor;

use nom::error::ErrorKind;
use rmp_serde as serde_mgpk;
use serde::Deserialize;

pub(crate) fn json_message<'a, D: Deserialize<'a>>(s: &'a [u8]) -> nom::IResult<&[u8], D> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<D>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub(crate) fn cbor_message<'a, D: Deserialize<'a>>(s: &'a [u8]) -> nom::IResult<&[u8], D> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<D>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub(crate) fn mgpk_message<'a, D: Deserialize<'a>>(s: &[u8]) -> nom::IResult<&[u8], D> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((&s[deser.get_ref().position() as usize..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}
