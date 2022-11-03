use serde::{Deserialize, Serialize};

use crate::{
    derivation::SelfAddressing, error::Error, event::SerializationFormats,
    event_parsing::path::MaterialPath, prefix::IdentifierPrefix, query::Timestamped,
};

use super::{
    key_event_message::KeyEvent, signature::Signature, EventMessage, EventTypeTag, SaidEvent,
    Typeable,
};

pub type ExchangeMessage = EventMessage<SaidEvent<Timestamped<Exchange>>>;

#[derive(Debug, Clone, PartialEq)]
pub struct SignedExchange {
    pub exchange_message: ExchangeMessage,
    pub signature: Vec<Signature>,
    // signature of event anchored in exn message in `a` field
    pub data_signature: (MaterialPath, Vec<Signature>),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum Exchange {
    #[serde(rename = "/fwd")]
    Fwd {
        #[serde(rename = "q")]
        args: FwdArgs,
        #[serde(rename = "a")]
        to_forward: EventMessage<KeyEvent>,
    },
}

impl Exchange {
    pub fn to_message(
        self,
        format: SerializationFormats,
        derivation: SelfAddressing,
    ) -> Result<ExchangeMessage, Error> {
        SaidEvent::<Timestamped<Exchange>>::to_message(Timestamped::new(self), format, derivation)
    }
}

impl Exchange {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Exchange::Fwd {
                args,
                to_forward: _,
            } => args.recipient_id.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FwdArgs {
    #[serde(rename = "pre")]
    pub recipient_id: IdentifierPrefix,
    pub topic: ForwardTopic,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardTopic {
    Multisig,
    Delegate,
}

impl Typeable for Exchange {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Exn
    }
}

#[test]
fn test_exn_serialization() -> Result<(), Error> {
    let exn_event = r#"{"v":"KERI10JSON0002f1_","t":"exn","d":"EPfS_lQ-hZIFX6ug1ggLlzVN09VnCWsubpE-jAC1Fx0W","dt":"2022-10-25T09:53:04.117732+00:00","r":"/fwd","q":{"pre":"EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","i":"EC61gZ9lCKmHAS7U5ehUfEbGId5rcY0D7MirFZHDQcE2","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[]}}"#; //-HABEKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4-AABAACJvddJrANYlrJ7CxEU9Z_AKJMxJZ7PNSyZeS4F6x2qZ2vTLtmD6mOOQ748TlddgB2ZFAMYt3xtzNdfrYNHS4IA-LAZ5AABAA-a-AABABBng3jTIIx_YUX-tS0caV1aV9QOvD5IM7WKt_wQz6Hvjm7nPhJgElP6K4Pu2JAIqCO93wBgBOx1DD3iawt0rb4"#;

    let parsed: ExchangeMessage = serde_json::from_str(exn_event).unwrap();
    let ser_deser = String::from_utf8(parsed.serialize()?).unwrap();

    assert_eq!(exn_event, ser_deser);

    let exchange = r#"{"v":"KERI10JSON000325_","t":"exn","d":"EJLdWmOy2wj3GfoPP5A1eIYAuP5fqpOUtWYgEjPG7DZp","dt":"2022-10-25T12:04:30.636995+00:00","r":"/fwd","q":{"pre":"EHpD0-CDWOdu5RJ8jHBSUkOqBZ3cXeDVHWNb_Ul89VI7","topic":"delegate"},"a":{"v":"KERI10JSON000249_","t":"dip","d":"EL_Atfv-taLFJVpu1Gzy50hCjsJ5Qvn7_sH1kuCGgwvl","i":"EL_Atfv-taLFJVpu1Gzy50hCjsJ5Qvn7_sH1kuCGgwvl","s":"0","kt":"2","k":["DOZlWGPfDHLMf62zSFzE8thHmnQUOgA3_Y-KpOyF9ScG","DHGb2qY9WwZ1sBnC9Ip0F-M8QjTM27ftI-3jTGF9mc6K"],"nt":"2","n":["EBvD5VIVvf6NpP9GRmTqu_Cd1KN0RKrKNfPJ-uhIxurj","EHlpcaxffvtcpoUUMTc6tpqAVtb2qnOYVk_3HRsZ34PH"],"bt":"3","b":["BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha","BLskRTInXnMxWaGqcpSyMgo0nYbalW99cGZESrz3zapM","BIKKuvBwpmDVA4Ds-EpL5bt9OqPzWPja2LigFYZN2YfX"],"c":[],"a":[],"di":"EHpD0-CDWOdu5RJ8jHBSUkOqBZ3cXeDVHWNb_Ul89VI7"}}"#; //-HABEJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1-AABAAAoAXJY8aWoWNgT6p9ww2XWOTJtOvcr1Y3Ej-XigsYyEufoj-vixPK8_en9PH3DFZwDf3vnwr4MbYOUU2h09kYD-LAv5AABAA-a-AACAABgMl2dGcyy8zT0x7HypyAEePk3R5WBjuPeA1hJRq-a4-8_F_8Dr4CLJGnyxkomJUSTODhv46UDCjdZZPXKMScMABDaYeZ1E7ekpj9qFFuwQnmrKq4H4LrlgTiGjeJ1aVLSDkM5f7UoUOCcPlwuNubhnS_69zT5SdDZMTXWKLtbJnUF"#;

    let parsed: ExchangeMessage = serde_json::from_str(exchange).unwrap();
    let ser_deser = String::from_utf8(parsed.serialize()?).unwrap();

    assert_eq!(exchange, ser_deser);
    Ok(())
}
