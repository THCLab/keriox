use cesrox::primitives::codes::self_addressing::dummy_prefix;
use keri::actor::prelude::SerializationFormats;
use keri::event_message::msg::TypedEvent;
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

use keri::{event_message::Typeable, prefix::IdentifierPrefix};
use said::version::SerializationInfo;

use crate::error::Error;

pub type ManagerTelEventMessage = TypedEvent<ManagementTelType, ManagerTelEvent>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ManagerTelEvent {
    // The Registry specific identifier will be self-certifying, self-addressing using its inception data for its derivation.
    // This requires a commitment to the anchor in the controlling KEL and necessitates the event location seal be included in
    // the event. The derived identifier is then set in the i field of the events in the management TEL.
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_type: ManagerEventType,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ManagementTelType {
    Vcp,
    Vrt,
}

impl Typeable for ManagerTelEvent {
    type TypeTag = ManagementTelType;
    fn get_type(&self) -> ManagementTelType {
        match self.event_type {
            ManagerEventType::Vcp(_) => ManagementTelType::Vcp,
            ManagerEventType::Vrt(_) => ManagementTelType::Vrt,
        }
    }
}

impl ManagerTelEvent {
    pub fn new(prefix: &IdentifierPrefix, sn: u64, event_type: ManagerEventType) -> Self {
        Self {
            prefix: prefix.to_owned(),
            sn,
            event_type,
        }
    }

    pub fn to_message(
        self,
        format: SerializationFormats,
        derivation: HashFunctionCode,
    ) -> Result<ManagerTelEventMessage, Error> {
        Ok(TypedEvent::<ManagementTelType, ManagerTelEvent>::new(
            format,
            derivation.into(),
            self,
        )?)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum ManagerEventType {
    /// Registry Inception Event
    Vcp(Inc),
    /// Registry Rotation Event
    Vrt(Rot),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Config {
    #[serde(rename = "NB")]
    NoBackers,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Inc {
    #[serde(rename = "ii")]
    pub issuer_id: IdentifierPrefix,

    #[serde(rename = "c")]
    pub config: Vec<Config>,

    #[serde(rename = "bt", with = "SerHex::<Compact>")]
    pub backer_threshold: u64,

    // list of backer identifiers for credentials associated with this registry
    #[serde(rename = "b")]
    pub backers: Vec<IdentifierPrefix>,
}

// TODO do we need this here? It's from keriox mostly.
/// Dummy Event
///
/// Used only to encapsulate the prefix derivation process for management inception (Vcp)
#[derive(Serialize, Debug, Clone)]
pub(crate) struct DummyEvent {
    #[serde(rename = "v")]
    serialization_info: SerializationInfo,
    #[serde(rename = "i")]
    prefix: String,
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    sn: u8,
    #[serde(flatten, rename = "t")]
    data: ManagerEventType,
}

impl DummyEvent {
    pub fn derive_inception_data(
        vcp: Inc,
        derivation: &HashFunctionCode,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Self::derive_data(ManagerEventType::Vcp(vcp), derivation, format)
    }

    fn derive_data(
        data: ManagerEventType,
        derivation: &HashFunctionCode,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Self {
            serialization_info: SerializationInfo::new(
                "KERI".to_string(),
                1,
                0,
                format,
                Self {
                    serialization_info: SerializationInfo::default(),
                    prefix: dummy_prefix(&derivation),
                    sn: 0,
                    data: data.clone(),
                }
                .encode()?
                .len(),
            ),
            prefix: dummy_prefix(&derivation),
            sn: 0,
            data,
        }
        .encode()
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info
            .serialize(&self)
            .map_err(|e| Error::EncodingError(e.to_string()))
    }
}

impl Inc {
    pub fn incept_self_addressing(
        self,
        derivation: &said::derivation::HashFunction,
        format: SerializationFormats,
    ) -> Result<ManagerTelEvent, Error> {
        Ok(ManagerTelEvent::new(
            &IdentifierPrefix::SelfAddressing(derivation.derive(
                &DummyEvent::derive_inception_data(self.clone(), &derivation.into(), format)?,
            )),
            0,
            ManagerEventType::Vcp(self),
        ))
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Rot {
    #[serde(rename = "p")]
    pub prev_event: SelfAddressingIdentifier,
    #[serde(rename = "ba")]
    pub backers_to_add: Vec<IdentifierPrefix>,
    #[serde(rename = "br")]
    pub backers_to_remove: Vec<IdentifierPrefix>,
}

#[cfg(test)]
mod tests {
    use keri::prefix::IdentifierPrefix;
    use said::derivation::{HashFunction, HashFunctionCode};
    use said::version::format::SerializationFormats;

    use crate::{
        error::Error,
        event::manager_event::{
            Config, Inc, ManagerEventType, ManagerTelEvent, ManagerTelEventMessage, Rot,
        },
        state::ManagerTelState,
    };

    #[test]
    fn test_serialization() -> Result<(), keri::prefix::error::Error> {
        // Manager inception
        // let vcp_raw = r#"{"v":"KERI10JSON000113_","t":"vcp","d":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPXBsg2LvxA","i":"EBoBPh3N5nr1tItAUCkXNx3vShB_Be6iiQPXBsg2LvxA","ii":"DAtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","c":["NB"],"bt":"0","b":[],"n":"A9XfpxIl1LcIkMhUSCCC8fgvkuX8gG9xK3SM-S8a8Y_U"}"#;
        let vcp_raw = r#"{"v":"KERI10JSON0000dc_","t":"vcp","d":"EIniznx8Vyltc0i-T7QwngvZkt_2xsT1PdsyRjq_1gAw","i":"EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s","s":"0","ii":"DHtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","c":[],"bt":"1","b":[]}"#;
        let vcp: ManagerTelEventMessage = serde_json::from_str(vcp_raw).unwrap();
        assert_eq!(
            vcp.data.prefix,
            "EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s".parse()?
        );
        assert_eq!(vcp.data.sn, 0);
        let expected_event_type = ManagerEventType::Vcp(Inc {
            issuer_id: "DHtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM".parse()?,
            config: vec![],
            backer_threshold: 1,
            backers: vec![],
        });
        assert_eq!(vcp.data.event_type, expected_event_type);
        assert_eq!(String::from_utf8(vcp.encode().unwrap()).unwrap(), vcp_raw);

        // let vcp_raw = r#"{"v":"KERI10JSON0000d7_","i":"EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s","ii":"DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","s":"0","t":"vcp","c":[],"bt":"1","b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}"#;
        let vcp_raw = r#"{"v":"KERI10JSON0000e0_","t":"vcp","d":"EBK9Otzl6zxt55LF095coJH7EBqlPIdrDC0f8bjeZYC9","i":"EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s","s":"0","ii":"DHtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM","c":["NB"],"bt":"1","b":["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"]}"#;
        let vcp: ManagerTelEvent = serde_json::from_str(vcp_raw).unwrap();
        assert_eq!(
            vcp.prefix,
            "EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s".parse()?
        );
        assert_eq!(vcp.sn, 0);
        let expected_event_type = ManagerEventType::Vcp(Inc {
            issuer_id: "DHtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM".parse()?,
            config: vec![Config::NoBackers],
            backer_threshold: 1,
            backers: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc".parse()?],
        });
        assert_eq!(vcp.event_type, expected_event_type);

        // Manager rotation
        // let vrt_raw = r#"{"v":"KERI10JSON0000aa_","i":"EE3Xv6CWwEMpW-99rhPD9IHFCR2LN5ienLVI8yG5faBw","p":"EY2L3ycqK9645aEeQKP941xojSiuiHsw4Y6yTW-PmsBg","s":"3","t":"vrt","bt":"1","br":[],"ba":[]}"#;
        let vrt_raw = r#"{"v":"KERI10JSON000102_","t":"vrt","d":"EBt83eunp22Zingg0UXHKXddBLeYQSBovkbr5mtQnwmB","i":"EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s","s":"1","p":"EIniznx8Vyltc0i-T7QwngvZkt_2xsT1PdsyRjq_1gAw","ba":["EHvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"],"br":[]}"#;
        let vrt: ManagerTelEvent = serde_json::from_str(vrt_raw).unwrap();
        assert_eq!(
            vrt.prefix,
            "EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s".parse()?
        );
        assert_eq!(vrt.sn, 1);
        let expected_event_type = ManagerEventType::Vrt(Rot {
            prev_event: "EIniznx8Vyltc0i-T7QwngvZkt_2xsT1PdsyRjq_1gAw"
                .parse()
                .unwrap(),
            backers_to_add: vec!["EHvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_remove: vec![],
        });
        assert_eq!(vrt.event_type, expected_event_type);

        Ok(())
    }

    #[test]
    fn test_apply_to() -> Result<(), Error> {
        // Construct inception event
        let pref: IdentifierPrefix = "EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s"
            .parse()
            .unwrap();
        let issuer_pref: IdentifierPrefix = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
            .parse()
            .unwrap();
        let event_type = ManagerEventType::Vcp(Inc {
            issuer_id: issuer_pref.clone(),
            config: vec![],
            backer_threshold: 1,
            backers: vec![],
        });
        let vcp = ManagerTelEvent::new(&pref, 0, event_type)
            .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        println!("\nvcp: {}", String::from_utf8(vcp.encode()?).unwrap());

        let state = ManagerTelState::default();
        let state = state.apply(&vcp)?;
        assert_eq!(state.issuer, issuer_pref);
        assert_eq!(state.backers.clone().unwrap(), vec![]);

        // Construct rotation event
        let prev_event = vcp.digest()?;
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_add: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_remove: vec![],
        });
        let vrt = ManagerTelEvent::new(&pref, 1, event_type.clone()).to_message(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
        )?;
        println!("\nvrt: {}", String::from_utf8(vrt.encode()?).unwrap());
        let state = state.apply(&vrt)?;
        assert_eq!(state.backers.clone().unwrap().len(), 1);
        assert_eq!(state.sn, 1);

        // Try applying event with improper sn.
        let out_of_order_vrt = ManagerTelEvent::new(&pref, 10, event_type).to_message(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
        )?;
        let err_state = state.apply(&out_of_order_vrt);
        assert!(err_state.is_err());

        // Try applying event with improper previous event
        let prev_event =
            HashFunction::from(HashFunctionCode::Blake3_256).derive("anything".as_bytes());
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_remove: vec![],
            backers_to_add: vec![],
        });
        let bad_previous = ManagerTelEvent::new(&pref, 2, event_type)
            .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        let err_state = state.apply(&bad_previous);
        assert!(err_state.is_err());

        // Construct next rotation event
        let prev_event = state.last.clone();
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_remove: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_add: vec![
                "DSEpNJeSJjxo6oAxkNE8eCOJg2HRPstqkeHWBAvN9XNU"
                    .parse()
                    .unwrap(),
                "Dvxo-P4W_Z0xXTfoA3_4DMPn7oi0mLCElOWJDpC0nQXw"
                    .parse()
                    .unwrap(),
            ],
        });
        let vrt = ManagerTelEvent::new(&pref, 2, event_type.clone())
            .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        let state = state.apply(&vrt)?;
        assert_eq!(state.backers.clone().unwrap().len(), 2);

        Ok(())
    }

    #[test]
    fn test_no_backers() -> Result<(), Error> {
        // Construct inception event
        let pref: IdentifierPrefix = "EVohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s"
            .parse()
            .unwrap();
        let issuer_pref: IdentifierPrefix = "DntNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM"
            .parse()
            .unwrap();
        let event_type = ManagerEventType::Vcp(Inc {
            issuer_id: issuer_pref.clone(),
            config: vec![Config::NoBackers],
            backer_threshold: 1,
            backers: vec![],
        });
        let vcp = ManagerTelEvent::new(&pref, 0, event_type)
            .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        println!("\nvcp: {}", String::from_utf8(vcp.encode()?).unwrap());

        let state = ManagerTelState::default();
        let state = state.apply(&vcp)?;
        assert_eq!(state.issuer, issuer_pref);
        assert_eq!(state.backers, None);

        // Construct rotation event
        let prev_event = HashFunction::from(HashFunctionCode::Blake3_256).derive(&vcp.encode()?);
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_add: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_remove: vec![],
        });
        let vrt = ManagerTelEvent::new(&pref, 1, event_type.clone())
            .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        // Try to update backers of backerless state.
        let state = state.apply(&vrt);
        assert!(state.is_err());

        Ok(())
    }
}
