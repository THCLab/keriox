use nom::{bytes::complete::take, multi::many0};

use self::group::parse_group;

use super::{
    codes::DerivationCode, message::event_message, parsing::from_text_to_bytes, EventType,
    ParsedData,
};

pub mod group;
pub mod primitives;

pub fn parse_primitive<C: DerivationCode>(
    code: C,
    stream: &[u8],
) -> nom::IResult<&[u8], (C, Vec<u8>)> {
    // TODO use parser for primitive code
    let (rest, _parsed_code) = take(code.code_size() as usize)(stream)?;
    let (rest, data) = take(code.value_size() as usize)(rest)?;
    // TODO don't remove bytes if code is 4 lenth
    let decoded = from_text_to_bytes(data).unwrap()[code.code_size() % 4..].to_vec();
    Ok((rest, (code, decoded)))
}

pub fn parse_payload(stream: &[u8]) -> nom::IResult<&[u8], EventType> {
    event_message(stream)
}

pub fn parse(stream: &[u8]) -> nom::IResult<&[u8], ParsedData> {
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
