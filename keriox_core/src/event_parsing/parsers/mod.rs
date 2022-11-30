use nom::{branch::alt, multi::many0};
use serde::Deserialize;

use crate::event_parsing::{parsers::group::parse_group, ParsedData};

use message::{cbor_message, json_message, mgpk_message};

pub mod group;
pub mod message;
pub mod primitives;

/// Tries to parse each possible serialization until it succeeds
pub fn parse_payload<'a, D: Deserialize<'a>>(stream: &'a [u8]) -> nom::IResult<&[u8], D> {
    alt((json_message::<D>, cbor_message::<D>, mgpk_message::<D>))(stream)
}

pub fn parse<'a, P: Deserialize<'a>>(stream: &'a [u8]) -> nom::IResult<&[u8], ParsedData<P>> {
    let (rest, payload) = parse_payload(stream)?;
    let (rest, attachments) = many0(parse_group)(rest)?;

    Ok((
        rest,
        ParsedData {
            payload,
            attachments,
        },
    ))
}

pub fn parse_many<'a, P: Deserialize<'a>>(
    stream: &'a [u8],
) -> nom::IResult<&[u8], Vec<ParsedData<P>>> {
    many0(parse::<P>)(stream)
}
