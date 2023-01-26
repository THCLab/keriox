use crate::{
    error::Error,
    event::vc_event::{VCEventMessage, VCEventType},
};
use keri::sai::{sad::SAD, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum TelState {
    NotIsuued,
    Issued(SelfAddressingPrefix),
    Revoked,
}

impl TelState {
    pub fn apply(&self, event: &VCEventMessage) -> Result<Self, Error> {
        let event_content = event.data.data.clone();
        match event_content.event_type {
            VCEventType::Bis(_iss) => match self {
                TelState::NotIsuued => {
                    if event_content.sn == 0 {
                        Ok(TelState::Issued(event.get_digest()))
                    } else {
                        Err(Error::Generic("Wrong sn".into()))
                    }
                }
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Brv(rev) => match self {
                TelState::Issued(last) => {
                    if rev.prev_event_hash.eq(last) && event_content.sn == 1 {
                        Ok(TelState::Revoked)
                    } else {
                        Err(Error::Generic("Previous event doesn't match".to_string()))
                    }
                }
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Iss(_iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(event.get_digest())),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Rev(rev) => match self {
                TelState::Issued(last) => {
                    if &rev.prev_event_hash == last {
                        Ok(TelState::Revoked)
                    } else {
                        Err(Error::Generic("Previous event doesn't match".to_string()))
                    }
                }
                _ => Err(Error::Generic("Wrong state".into())),
            },
        }
    }
}

impl Default for TelState {
    fn default() -> Self {
        TelState::NotIsuued
    }
}

#[test]
fn test_apply() -> Result<(), Error> {
    let bis_raw = r#"{"v":"KERI10JSON000162_","t":"bis","d":"EFXbFFjdUNRgg_blTx76RAdcIoRoLtPl5tA3yAw5vS9W","i":"EC8Oej-3HAUpBY_kxzBK3B-0RV9j4dXw1H0NRKxJg7g-","s":"0","ii":"EKKJ0FoLxO1TYmyuprguKO7kJ7Hbn0m0Wuk5aMtSrMtY","ra":{"i":"EIZlA3TANi3p8vEu4VQMjPnY0sPFAag1ekIwyyR6lAsq","s":"0","d":"EFSL6HebpbWsxKxfdS4t6NbKTdO4hAUIAxvhmWVf3Z8o"},"dt":"2023-01-10T10:36:50.842679+00:00"}"#;
    let bis_ev: VCEventMessage = serde_json::from_str(&bis_raw).unwrap();
    assert_eq!(serde_json::to_string(&bis_ev).unwrap(), bis_raw);

    let brv_raw = r#"{"v":"KERI10JSON000161_","t":"brv","d":"ENJrZygsUPsqzxjrmgXIjweuQX5I2lXbgcGFn7iEyDyG","i":"EC8Oej-3HAUpBY_kxzBK3B-0RV9j4dXw1H0NRKxJg7g-","s":"1","p":"EFXbFFjdUNRgg_blTx76RAdcIoRoLtPl5tA3yAw5vS9W","ra":{"i":"EIZlA3TANi3p8vEu4VQMjPnY0sPFAag1ekIwyyR6lAsq","s":"0","d":"EFSL6HebpbWsxKxfdS4t6NbKTdO4hAUIAxvhmWVf3Z8o"},"dt":"2023-01-10T10:36:50.843652+00:00"}"#;
    let brv_ev: VCEventMessage = serde_json::from_str(&brv_raw).unwrap();
    assert_eq!(serde_json::to_string(&brv_ev).unwrap(), brv_raw);

    let state = TelState::default();
    let state = state.apply(&bis_ev)?;
    assert!(matches!(state, TelState::Issued(_)));

    if let TelState::Issued(last) = state.clone() {
        match brv_ev.data.data.event_type {
            VCEventType::Brv(ref brv) => assert!(brv.prev_event_hash == last),
            _ => (),
        };
    }
    let state = state.apply(&brv_ev)?;
    assert_eq!(state, TelState::Revoked);

    let state = state.apply(&brv_ev);
    assert!(state.is_err());

    Ok(())
}
