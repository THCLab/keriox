use nom::bytes::complete::take;

use super::{codes::DerivationCode, parsing::from_text_to_bytes};

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
