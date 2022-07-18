use serde::{Serialize, Deserialize};

use crate::{prefix::IdentifierPrefix, error::Error, event_parsing::Attachment};

use super::{EventMessage, SaidEvent, key_event_message::KeyEvent, Typeable, EventTypeTag};

pub type ExchangeMessage = EventMessage<SaidEvent<Exchange>>;

#[derive(Debug, Clone, PartialEq)]
pub struct SignedExchange {
    pub exchange_message: ExchangeMessage,
    pub attachment: Attachment,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "r")]
pub enum Exchange {
    #[serde(rename = "/fwd")]
    Fwd {
        #[serde(rename = "q")]
        args: FwdArgs,
        #[serde(rename = "a")]
        to_forward: EventMessage<KeyEvent>
    },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct FwdArgs {
    #[serde(rename = "pre")]
    recipient_id: IdentifierPrefix,
    topic: ForwardTopic
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ForwardTopic {
    Multisig
}

impl Typeable for Exchange {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Exn
    }
}

#[test]
fn test_exn_serialization() -> Result<(), Error> {
    let exn_event = r#"{"v":"KERI10JSON0002c9_","t":"exn","d":"Eru6l4p3-r6KJkT1Ac8r5XWuQMsD91-c80hC7lASOoZI","r":"/fwd","q":{"pre":"E-4-PsMBN0YEKyTl3zL0zulWcBehdaaG6Go5cMc0BzQ8","topic":"multisig"},"a":{"v":"KERI10JSON000215_","t":"icp","d":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","i":"EOWwyMU3XA7RtWdelFt-6waurOTH_aW_Z9VTaU-CshGk","s":"0","kt":"2","k":["DQKeRX-2dXdSWS-EiwYyiQdeIwesvubEqnUYC5vsEyjo","D-U6Sc6VqQC3rDuD2wLF3oR8C4xQyWOTMp4zbJyEnRlE"],"nt":"2","n":["ENVtv0_G68psQhfWB-ZyVH1lndLli2LSmfSxxszNufoI","E6UpCouA9mZA03hMFJLrhA0SvwR4HVNqf2wrZM-ydTSI"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}}"#;//-HABEozYHef4je02EkMOA1IKM65WkIdSjfrL7XWDk_JzJL9o-AABAArQYXZsfglDLnZrGGYUyhNzriWJTSuKjqRrcrDik3zch94IQ9tjQwz0K0iikVCENApxSSo9tBQT7pz9d9G1O0DQ-LAZ5AABAA-a-AABAAFjjD99-xy7J0LGmCkSE_zYceED5uPF4q7l8J23nNQ64U-oWWulHI5dh3cFDWT4eICuEQCALdh8BO5ps-qx0qBA"#;

	let parsed: ExchangeMessage = serde_json::from_str(exn_event).unwrap();
	let ser_deser = serde_json::to_string(&parsed).unwrap();

	assert_eq!(exn_event, ser_deser);

	Ok(())
}