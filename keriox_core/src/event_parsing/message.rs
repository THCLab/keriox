use std::io::Cursor;

use nom::{branch::alt, combinator::map, error::ErrorKind, multi::many0, sequence::pair};
use rmp_serde as serde_mgpk;
use serde::Deserialize;
#[cfg(feature = "query")]
use serde::Serialize;

use crate::event_message::serialization_info::SerializationInfo;
use crate::event_message::{cesr_adapter::EventType, exchange::Exchange};
#[cfg(feature = "query")]
use crate::event_message::{SaidEvent, Typeable};
use crate::event_parsing::parsers::group::parse_group;
#[cfg(feature = "query")]
use crate::query::Timestamped;
use crate::{
    event::{receipt::Receipt, EventMessage},
    event_message::{key_event_message::KeyEvent, Digestible},
    event_parsing::ParsedData,
};

fn json_message<'a, D: Deserialize<'a> + Digestible>(
    s: &'a [u8],
) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_json::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn cbor_message<'a, D: Deserialize<'a>>(s: &'a [u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut stream = serde_cbor::Deserializer::from_slice(s).into_iter::<EventMessage<D>>();
    match stream.next() {
        Some(Ok(event)) => Ok((&s[stream.byte_offset()..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

fn mgpk_message<'a, D: Deserialize<'a>>(s: &[u8]) -> nom::IResult<&[u8], EventMessage<D>> {
    let mut deser = serde_mgpk::Deserializer::new(Cursor::new(s));
    match Deserialize::deserialize(&mut deser) {
        Ok(event) => Ok((&s[deser.get_ref().position() as usize..], event)),
        _ => Err(nom::Err::Error((s, ErrorKind::IsNot))),
    }
}

pub fn message<'a, D: Deserialize<'a> + Digestible>(
    s: &'a [u8],
) -> nom::IResult<&[u8], EventMessage<D>> {
    alt((json_message::<D>, cbor_message::<D>, mgpk_message::<D>))(s)
}

pub fn key_event_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<KeyEvent>(s).map(|d| (d.0, EventType::KeyEvent(d.1)))
}

pub fn receipt_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<Receipt>(s).map(|d| (d.0, EventType::Receipt(d.1)))
}

pub fn exchange_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    message::<SaidEvent<Timestamped<Exchange>>>(s).map(|d| (d.0, EventType::Exn(d.1)))
}

#[cfg(any(feature = "query", feature = "oobi"))]
fn timestamped<'a, D: Serialize + Deserialize<'a> + Typeable>(
    s: &'a [u8],
) -> nom::IResult<&[u8], EventMessage<SaidEvent<Timestamped<D>>>> {
    message::<SaidEvent<Timestamped<D>>>(s).map(|d| (d.0, d.1))
}

#[cfg(feature = "query")]
pub fn query_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    use crate::query::query_event::Query;

    timestamped::<Query>(s).map(|d| (d.0, EventType::Qry(d.1)))
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn reply_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    use crate::query::reply_event::ReplyRoute;

    timestamped::<ReplyRoute>(s).map(|d| (d.0, EventType::Rpy(d.1)))
}

pub fn event_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    #[cfg(any(feature = "query", feature = "oobi"))]
    {
        alt((notice_message, op_message))(s)
    }
    #[cfg(not(any(feature = "query", feature = "oobi")))]
    {
        notice_message(s)
    }
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn op_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    alt((query_message, reply_message, exchange_message))(s)
}

pub fn notice_message(s: &[u8]) -> nom::IResult<&[u8], EventType> {
    alt((key_event_message, receipt_message))(s)
}

pub fn signed_message(s: &[u8]) -> nom::IResult<&[u8], ParsedData<EventType>> {
    map(
        pair(event_message, many0(parse_group)),
        |(event, attachments)| ParsedData {
            payload: event,
            attachments,
        },
    )(s)
}

pub fn signed_notice(s: &[u8]) -> nom::IResult<&[u8], ParsedData<EventType>> {
    map(
        pair(notice_message, many0(parse_group)),
        |(event, attachments)| ParsedData {
            payload: event,
            attachments,
        },
    )(s)
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn signed_op(s: &[u8]) -> nom::IResult<&[u8], ParsedData<EventType>> {
    map(
        pair(op_message, many0(parse_group)),
        |(event, attachments)| ParsedData {
            payload: event,
            attachments,
        },
    )(s)
}

pub fn signed_event_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<ParsedData<EventType>>> {
    many0(signed_message)(s)
}

pub fn signed_notice_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<ParsedData<EventType>>> {
    many0(signed_notice)(s)
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn signed_op_stream(s: &[u8]) -> nom::IResult<&[u8], Vec<ParsedData<EventType>>> {
    many0(signed_op)(s)
}

// TESTED: OK
fn json_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_json::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
fn cbor_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_cbor::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

// TODO: Requires testing
fn mgpk_version(data: &[u8]) -> nom::IResult<&[u8], SerializationInfo> {
    match serde_mgpk::from_slice(data) {
        Ok(vi) => Ok((data, vi)),
        _ => Err(nom::Err::Error((data, ErrorKind::IsNot))),
    }
}

pub(crate) fn version<'a>(data: &'a [u8]) -> nom::IResult<&[u8], SerializationInfo> {
    alt((json_version, cbor_version, mgpk_version))(data).map(|d| (d.0, d.1))
}

#[test]
fn test_version_parse() {
    let json = br#""KERI10JSON00014b_""#;
    let json_result = version(json);
    assert!(json_result.is_ok());
}
