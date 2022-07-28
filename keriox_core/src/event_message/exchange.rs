use serde::{Deserialize, Serialize};

use crate::{error::Error, event_parsing::path::MaterialPath, prefix::IdentifierPrefix};

use super::{
    key_event_message::KeyEvent, signature::Signature, EventMessage, EventTypeTag, SaidEvent,
    Typeable,
};

pub type ExchangeMessage = EventMessage<SaidEvent<Exchange>>;

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
}

impl Typeable for Exchange {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Exn
    }
}

#[test]
fn test_exn_serialization() -> Result<(), Error> {
    let exn_event = r#"{"v":"KERI10JSON0002c9_","t":"exn","d":"Eru6l4p3-r6KJkT1Ac8r5XWuQMsD91-c80hC7lASOoZI","r":"/fwd","q":{"pre":"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","i":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","s":"0","kt":"2","k":["DQKeRX-2dXdSWS-EiwYyiQdeIwesvubEqnUYC5vsEyjo","D-U6Sc6VqQC3rDuD2wLF3oR8C4xQyWOTMp4zbJyEnRlE"],"nt":"2","n":["ENVtv0_G68psQhfWB-ZyVH1lndLli2LSmfSxxszNufoI","E6UpCouA9mZA03hMFJLrhA0SvwR4HVNqf2wrZM-ydTSI"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}}"#;

    let parsed: ExchangeMessage = serde_json::from_str(exn_event).unwrap();
    let ser_deser = serde_json::to_string(&parsed).unwrap();

    assert_eq!(exn_event, ser_deser);

    Ok(())
}
