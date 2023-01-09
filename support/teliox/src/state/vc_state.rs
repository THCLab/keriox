use crate::{
    error::Error,
    event::vc_event::{VCEvent, VCEventType},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum TelState {
    NotIsuued,
    // Issued state has last event as argument
    Issued(Vec<u8>),
    Revoked,
}

impl TelState {
    pub fn apply(&self, event: &VCEvent) -> Result<Self, Error> {
        match event.event_type.clone() {
            VCEventType::Bis(_iss) => match self {
                TelState::NotIsuued => {
                    if event.sn == 0 {
                        Ok(TelState::Issued(event.serialize()?))
                    } else {
                        Err(Error::Generic("Wrong sn".into()))
                    }
                }
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Brv(rev) => match self {
                TelState::Issued(last) => {
                    if rev.prev_event_hash.verify_binding(last) && event.sn == 1 {
                        Ok(TelState::Revoked)
                    } else {
                        Err(Error::Generic("Previous event doesn't match".to_string()))
                    }
                }
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Iss(_iss) => match self {
                TelState::NotIsuued => Ok(TelState::Issued(event.serialize()?)),
                _ => Err(Error::Generic("Wrong state".into())),
            },
            VCEventType::Rev(rev) => match self {
                TelState::Issued(last) => {
                    if rev.prev_event_hash.verify_binding(last) {
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
    use crate::event::vc_event::TimestampedVCEvent;
    let bis_raw = r#"{"v":"KERI10JSON000126_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"bis","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00+00:00"}"#;
    let bis_ev: TimestampedVCEvent = serde_json::from_str(&bis_raw).unwrap();
    assert_eq!(serde_json::to_string(&bis_ev).unwrap(), bis_raw);

    let brv_raw = r#"{"v":"KERI10JSON000125_","i":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"1","t":"brv","p":"EAw68wa_F60wtPJ8MPsz7UOv9wRMI6Yi5aeJjKL2ijHs","ra":{"i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","s":"3","d":"Ezpq06UecHwzy-K9FpNoRxCJp2wIGM9u2Edk-PLMZ1H4"},"dt":"2021-01-01T00:00:00+00:00"}"#;
    let brv_ev: TimestampedVCEvent = serde_json::from_str(&brv_raw).unwrap();
    assert_eq!(serde_json::to_string(&brv_ev).unwrap(), brv_raw);

    let state = TelState::default();
    let state = state.apply(&bis_ev.event)?;
    assert!(matches!(state, TelState::Issued(_)));

    if let TelState::Issued(last) = state.clone() {
        match brv_ev.event.event_type {
            VCEventType::Brv(ref brv) => assert!(brv.prev_event_hash.verify_binding(&last)),
            _ => (),
        };
    }
    let state = state.apply(&brv_ev.event)?;
    assert_eq!(state, TelState::Revoked);

    let state = state.apply(&brv_ev.event);
    assert!(state.is_err());

    Ok(())
}
