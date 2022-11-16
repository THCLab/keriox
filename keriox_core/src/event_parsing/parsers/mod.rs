use nom::{bytes::complete::take, multi::many0};
use serde::Deserialize;

use self::group::parse_group;

use super::{ParsedData, Payload};

pub mod group;
pub mod primitives;

pub fn parse_payload<'a, P: Payload + Deserialize<'a>>(stream: &'a [u8]) -> nom::IResult<&[u8], P> {
    let (rest, event) = take(P::get_len(stream).unwrap())(stream)?;
    let parsed_event: P = serde_json::from_slice(event).unwrap();
    Ok((rest, parsed_event))
}

pub fn parse<'a, P: Payload + Deserialize<'a>>(
    stream: &'a [u8],
) -> nom::IResult<&[u8], ParsedData<P>> {
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

#[test]
fn test_signed_event() {
    use crate::event_message::cesr_adapter::EventType;
    // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2255
    let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let parsed = parse::<EventType>(stream);
    assert!(parsed.is_ok());
    assert_eq!(parsed.unwrap().1.to_cesr().unwrap(), stream);
}
