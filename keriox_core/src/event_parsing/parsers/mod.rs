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

#[cfg(test)]
pub mod test {
    use crate::{
        event_message::cesr_adapter::EventType,
        event_parsing::parsers::{parse, parse_many},
    };

    #[test]
    fn test_signed_event() {
        use crate::event_message::cesr_adapter::EventType;
        // taken from KERIPY: tests/core/test_eventing.py::test_multisig_digprefix#2255
        let stream = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
        let parsed = parse::<EventType>(stream);
        assert!(parsed.is_ok());
        assert_eq!(parsed.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[test]
    fn test_key_event_parsing() {
        // Inception event.
        let stream = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"EMW0zK3bagYPO6gx3w7Ua90f-I7x5kGIaI4Xeq9W8_As","i":"BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0","kt":"1","k":["BFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Rotation event.
        let stream = br#"{"v":"KERI10JSON000160_","t":"rot","d":"EFl8nvRCbN2xQJI75nBXp-gaXuHJw8zheVjwMN_rB-pb","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"1","p":"EJQUyxnzIAtmZPoq9f4fExeGN0qfJmaFnUEKTwIiTBPj","kt":"1","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Interaction event without seals.
        let stream = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"2","p":"ECauhEzA4DJDXVDnNQiGQ0sKXa6sx_GgS8Ebdzm4E-kQ","a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Interaction event with seal.
        let stream = br#"{"v":"KERI10JSON00013a_","t":"ixn","d":"EJtQndkvwnMpVGE5oVVbLWSCm-jLviGw1AOOkzBvNwsS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":[{"i":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj","s":"0","d":"EHng2fV42DdKb5TLMIs6bbjFkPNmIdQ5mSFn6BTnySJj"}]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Delegated inception event.
        let stream = br#"{"v":"KERI10JSON00015f_","t":"dip","d":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"0","kt":"1","k":["DB4GWvru73jWZKpNgMQp8ayDRin0NG0Ymn_RXQP_v-PQ"],"nt":"1","n":["EIf-ENw7PrM52w4H-S7NGU2qVIfraXVIlV9hEAaMHg7W"],"bt":"0","b":[],"c":[],"a":[],"di":"EAdHxtdjCQUM-TVO8CgJAKb8ykXsFe4u9epTUQFCL7Yd"}"#;
        let event = parse::<EventType>(stream);
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);

        // Delegated rotation event.
        let stream = br#"{"v":"KERI10JSON000160_","t":"drt","d":"EMBBBkaLV7i6wNgfz3giib2ItrHsr548mtIflW0Hrbuv","i":"EN3PglLbr4mJblS4dyqbqlpUa735hVmLOhYUbUztxaiH","s":"4","p":"EANkcl_QewzrRSKH2p9zUskHI462CuIMS_HQIO132Z30","kt":"1","k":["DPLt4YqQsWZ5DPztI32mSyTJPRESONvE9KbETtCVYIeH"],"nt":"1","n":["EIsKL3B6Zz5ICGxCQp-SoLXjwOrdlSbLJrEn21c2zVaU"],"bt":"0","br":[],"ba":[],"a":[]}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[test]
    fn test_receipt_parsing() {
        // Receipt event
        let stream = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EKKccCumVQdgxvsrSXvuTtjmS28Xqf3zRJ8T6peKgl9J","i":"DFs8BBx86uytIM0D2BhsE5rrqVIT8ef8mflpNceHo4XH","s":"0"}"#;
        let event = parse::<EventType>(stream);
        assert!(event.is_ok());
        assert_eq!(event.unwrap().1.to_cesr().unwrap(), stream);
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_qry() {
        // taken from keripy keripy/tests/core/test_eventing.py::test_messegize
        let qry_event = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EGN68_seecuzXQO15FFGJLVwZCBCPYW-hy29fjWWPQbp","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DAvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}"#;
        let rest = "something more".as_bytes();
        let stream = [qry_event, rest].concat();

        let (_extra, event) = parse::<EventType>(&stream).unwrap();
        assert!(matches!(event.payload, EventType::Qry(_)));
        assert_eq!(&event.to_cesr().unwrap(), qry_event);
    }

    #[test]
    fn test_exn() {
        let exn_event = br#"{"v":"KERI10JSON0002f1_","t":"exn","d":"EBLqTGJXK8ViUGXMOO8_LXbetpjJX8CY_SbA134RIZmf","dt":"2022-10-25T09:53:04.119676+00:00","r":"/fwd","q":{"pre":"EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}}-HABEJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1-AABAAArUSuSpts5zDQ7CgPcy305IxhAG8lOjf-r_d5yYQXp18OD9No_gd2McOOjGWMfjyLVjDK529pQcbvNv9Uwc6gH-LAZ5AABAA-a-AABAABYHc_lpuYF3SPNWvyPjzek7yquw69Csc6pLv5vrXHkFAFDcwNNTVxq7ZpxpqOO0CAIS-9Qj1zMor-cwvMHAmkE')"#;

        let (_extra, event) = parse::<EventType>(exn_event).unwrap();
        assert!(matches!(event.payload, EventType::Exn(_)));
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_reply() {
        let rpy = br#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EYFMuK9IQmHvq9KaJ1r67_MMCq5GnQEgLyN9YPamR3r0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAAAwEOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30-AABAAYsqumzPM0bIo04gJ4Ln0zAOsGVnjHZrFjjjS49hGx_nQKbXuD1D4J_jNoEa4TPtPDnQ8d0YcJ4TIRJb-XouJBg"#;
        let rest = "something more".as_bytes();
        let stream = [rpy, rest].concat();

        let (_extra, event) = parse::<EventType>(&stream).unwrap();
        assert!(matches!(event.payload, EventType::Rpy(_)));
    }

    #[cfg(feature = "query")]
    #[test]
    fn test_signed_qry() {
        use nom::Needed;

        // Taken from keripy/tests/core/test_eventing.py::test_messagize (line 1471)
        let stream = br#"{"v":"KERI10JSON0000c9_","t":"qry","d":"E-WvgxrllmjGFhpn0oOiBkAVz3-dEm3bbiV_5qwj81xo","dt":"2021-01-01T00:00:00.000000+00:00","r":"log","rr":"","q":{"i":"DyvCLRr5luWmp7keDvDuLP0kIqcyBYq79b3Dho1QvrjI"}}-VAj-HABEZOIsLsfrVdBvULlg3Hg_Y1r-hadS82ZpglBLojPIQhg-AABAAuISeZIVO_wXjIrGJ-VcVMxr285OkKzAqVEQqVPFx8Ht2A9GQFB-zRA18J1lpqVphOnnXbTc51WR4uAvK90EHBg"#;
        let se = parse::<EventType>(&stream[..stream.len() - 1]);
        assert!(matches!(se, Err(nom::Err::Incomplete(Needed::Size(1)))));
        let se = parse::<EventType>(stream);
        assert!(se.is_ok());
    }

    #[test]
    fn test_signed_events_stream() {
        // Taken from keripy/tests/core/test_kevery.py::test kevery
        let kerl_str= br#"{"v":"KERI10JSON000120_","t":"icp","d":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"0","kt":"1","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA"],"n":"EPYuj8mq_PYYsoBKkzX1kxSPGYBWaIya3slgCOyOtlqU","bt":"0","b":[],"c":[],"a":[]}-AABAA0aSisI4ZZTH_6JCqsvAsEpuf_Jq6bDbvPWj_eCDnAGbSARqYHipNs-9W7MHnwnMfIXwLpcoJkKGrQ-SiaklhAw{"v":"KERI10JSON000155_","t":"rot","d":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"1","p":"EG4EuTsxPiRM7soX10XXzNsS1KqXKUp8xsQ-kW_tWHoI","kt":"1","k":["DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI"],"n":"E-dapdcC6XR1KWmWDsNl4J_OxcGxNZw1Xd95JH5a34fI","bt":"0","br":[],"ba":[],"a":[]}-AABAAwoiqt07w2UInzzo2DmtwkBfqX1-tTO4cYk_7YdlbJ95qA7PO5sEUkER8fZySQMNCVh64ruAh1yoew3TikwVGAQ{"v":"KERI10JSON000155_","t":"rot","d":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"2","p":"Ej30AgJV14mTTs427F3kILLrP_l03a27APg2FBO0-QtA","kt":"1","k":["DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"EKrLE2h2nh3ClyJNEjKaikHWT7G-ngimNpK-QgVQv9As","bt":"0","br":[],"ba":[],"a":[]}-AABAAW_RsDfAcHkknyzh9oeliH90KGPJEI8AP3rJPyuTnpVg8yOVtSIp_JFlyRwjV5SEQOqddAcRV6JtaQO8oXtWFCQ{"v":"KERI10JSON0000cb_","t":"ixn","d":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"3","p":"EmtXXRjyz6IdeX4201BgXKRDBm74gGqJF2r2umMMAL6I","a":[]}-AABAAlB0Ui5NHJpcifXUB6bAutmpZkhSgwxyI5jEZ2JGVBgTI02sC0Ugbq3q0EpOae7ruXW-eabUz2s0FAs26jGwVBg{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"4","p":"EY7E4RJXPe7FF1zQPbpSMIY-TYz9eAmNIhuprPYqTQ5o","a":[]}-AABAAWITFg460TXvYvxxzN62vpqpLs-vGgeGAbd-onY3DYxd5e3AljHh85pTum4Ha48F5dui9IVYqYvuYJCG8p8KvDw{"v":"KERI10JSON000155_","t":"rot","d":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"5","p":"ENVzbZieVIjYLYkPWQy0gfua11KqdRG-oku5Ut8Dl6hU","kt":"1","k":["DKPE5eeJRzkRTMOoRGVd2m18o8fLqM2j9kaxLhV3x8AQ"],"n":"EhVTfJFfl6L0Z0432mDUxeaqB_hlWPJ2qUuzG95gEyJU","bt":"0","br":[],"ba":[],"a":[]}-AABAAnqz-vnMx1cqe_SkcIrlx092UhbYzvvkHXjtxfuNDDcqnVtH11_8ZPaWomn3n963_bFTjjRhJaAH1SK8LU7s1DA{"v":"KERI10JSON0000cb_","t":"ixn","d":"Ek9gvRbkCt-wlgQBoV1PGm2iI__gaPURtJ3YrNFsXLzE","i":"DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","s":"6","p":"E6wrLhilpPo4ePq7m7ZccEcKjwPD2q9mqzLUb_aO2Hi0","a":[]}-AABAAwGGWMNDpu8t4NuF_3M0jnkn3P063oUHmluwRwsyCg5tIvu-BfwIJRruAsCKry4LaI84dJAfAT5KJnG8xz9lJCw"#;
        let (rest, messages) = parse_many::<EventType>(kerl_str).unwrap();

        assert!(rest.is_empty());
        assert_eq!(messages.len(), 7);
    }
}
