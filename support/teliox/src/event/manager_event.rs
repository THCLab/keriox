use serde::{de, Deserialize, Deserializer, Serialize};
use serde_hex::{Compact, SerHex};

use keri::{
    event::SerializationFormats,
    event_message::{serialization_info::SerializationInfo, EventMessage, SaidEvent, Typeable},
    event_parsing::codes::self_addressing::dummy_prefix,
    prefix::IdentifierPrefix,
    sai::{derivation::SelfAddressing, SelfAddressingPrefix},
};
use serde_json::Value;

use crate::error::Error;

pub type ManagerTelEventMessage = EventMessage<SaidEvent<ManagerTelEvent>>;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ManagerTelEvent {
    // The Registry specific identifier will be self-certifying, self-addressing using its inception data for its derivation.
    // This requires a commitment to the anchor in the controlling KEL and necessitates the event location seal be included in
    // the event. The derived identifier is then set in the i field of the events in the management TEL.
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten, rename = "t")]
    pub event_type: ManagerEventType,
}

#[derive(Serialize, Deserialize, Debug)]
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

impl<'de> Deserialize<'de> for ManagerEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Helper struct for adding tag to properly deserialize 't' field
        #[derive(Deserialize, Debug)]
        struct EventType {
            t: ManagementTelType,
        }

        let v = Value::deserialize(deserializer)?;
        let m = EventType::deserialize(&v).map_err(de::Error::custom)?;
        match m.t {
            ManagementTelType::Vcp => Ok(ManagerEventType::Vcp(
                Inc::deserialize(&v).map_err(de::Error::custom)?,
            )),
            ManagementTelType::Vrt => Ok(ManagerEventType::Vrt(
                Rot::deserialize(&v).map_err(de::Error::custom)?,
            )),
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
        derivation: SelfAddressing,
    ) -> Result<ManagerTelEventMessage, Error> {
        Ok(SaidEvent::<ManagerTelEvent>::to_message(
            self, format, derivation,
        )?)
    }
}

// #[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
// pub struct ManagerIdentifier {}

#[derive(Serialize, Debug, Clone, PartialEq)]
#[serde(untagged, rename_all = "lowercase")]
pub enum ManagerEventType {
    Vcp(Inc),
    Vrt(Rot),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Config {
    #[serde(rename = "NB")]
    NoBackers,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        Self::derive_data(ManagerEventType::Vcp(vcp), derivation, format)
    }

    fn derive_data(
        data: ManagerEventType,
        derivation: &SelfAddressing,
        format: SerializationFormats,
    ) -> Result<Vec<u8>, Error> {
        use keri::event_parsing::codes::self_addressing::SelfAddressing as CesrCode;
        let derivation_code: CesrCode = derivation.clone().into();
        Ok(Self {
            serialization_info: SerializationInfo::new(
                format,
                Self {
                    serialization_info: SerializationInfo::new(format, 0),
                    prefix: dummy_prefix(&derivation_code),
                    sn: 0,
                    data: data.clone(),
                }
                .serialize()?
                .len(),
            ),
            prefix: dummy_prefix(&derivation_code),
            sn: 0,
            data: data,
        }
        .serialize()?)
    }

    fn serialize(&self) -> Result<Vec<u8>, Error> {
        self.serialization_info
            .kind
            .encode(&self)
            .map_err(|e| Error::KeriError(e))
    }

    // fn dummy_prefix(derivation: &SelfAddressing) -> String {
    //     std::iter::repeat("#")
    //         .take(derivation.code_len() + derivation.derivative_b64_len())
    //         .collect::<String>()
    // }
}

impl Inc {
    pub fn incept_self_addressing(
        self,
        derivation: &keri::sai::derivation::SelfAddressing,
        format: SerializationFormats,
    ) -> Result<ManagerTelEvent, Error> {
        Ok(ManagerTelEvent::new(
            &IdentifierPrefix::SelfAddressing(derivation.derive(
                &DummyEvent::derive_inception_data(self.clone(), &derivation, format)?,
            )),
            0,
            ManagerEventType::Vcp(self),
        ))
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Rot {
    #[serde(rename = "p")]
    pub prev_event: SelfAddressingPrefix,
    #[serde(rename = "ba")]
    pub backers_to_add: Vec<IdentifierPrefix>,
    #[serde(rename = "br")]
    pub backers_to_remove: Vec<IdentifierPrefix>,
}

#[cfg(test)]
mod tests {
    use keri::{
        event::SerializationFormats, event_message::Digestible, prefix::IdentifierPrefix,
        sai::derivation::SelfAddressing,
    };

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
            vcp.event.content.prefix,
            "EFohdnN33-vdNOTPYxeTQIWVzRKtzZzBoiBSGYSSnD0s".parse()?
        );
        assert_eq!(vcp.event.content.sn, 0);
        let expected_event_type = ManagerEventType::Vcp(Inc {
            issuer_id: "DHtNTPnDFBnmlO6J44LXCrzZTAmpe-82b7BmQGtL4QhM".parse()?,
            config: vec![],
            backer_threshold: 1,
            backers: vec![],
        });
        assert_eq!(vcp.event.content.event_type, expected_event_type);
        assert_eq!(
            String::from_utf8(vcp.serialize().unwrap()).unwrap(),
            vcp_raw
        );

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
            prev_event: "EIniznx8Vyltc0i-T7QwngvZkt_2xsT1PdsyRjq_1gAw".parse()?,
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
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        println!("\nvcp: {}", String::from_utf8(vcp.serialize()?).unwrap());

        let state = ManagerTelState::default();
        let state = state.apply(&vcp)?;
        assert_eq!(state.issuer, issuer_pref);
        assert_eq!(state.backers.clone().unwrap(), vec![]);

        // Construct rotation event
        let prev_event = vcp.event.get_digest();
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_add: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_remove: vec![],
        });
        let vrt = ManagerTelEvent::new(&pref, 1, event_type.clone())
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        println!("\nvrt: {}", String::from_utf8(vrt.serialize()?).unwrap());
        let state = state.apply(&vrt)?;
        assert_eq!(state.backers.clone().unwrap().len(), 1);
        assert_eq!(state.sn, 1);

        // Try applying event with improper sn.
        let out_of_order_vrt = ManagerTelEvent::new(&pref, 10, event_type)
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        let err_state = state.apply(&out_of_order_vrt);
        assert!(err_state.is_err());

        // Try applying event with improper previous event
        let prev_event = SelfAddressing::Blake3_256.derive("anything".as_bytes());
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_remove: vec![],
            backers_to_add: vec![],
        });
        let bad_previous = ManagerTelEvent::new(&pref, 2, event_type)
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
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
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        let state = state.apply(&vrt)?;
        assert_eq!(state.backers.clone().unwrap().len(), 2);

        Ok(())
    }

    #[test]
    fn test_no_backers() -> Result<(), Error> {
        use keri::sai::derivation::SelfAddressing;
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
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        println!("\nvcp: {}", String::from_utf8(vcp.serialize()?).unwrap());

        let state = ManagerTelState::default();
        let state = state.apply(&vcp)?;
        assert_eq!(state.issuer, issuer_pref);
        assert_eq!(state.backers, None);

        // Construct rotation event
        let prev_event = SelfAddressing::Blake3_256.derive(&vcp.serialize()?);
        let event_type = ManagerEventType::Vrt(Rot {
            prev_event,
            backers_to_add: vec!["EXvR3p8V95W8J7Ui4-mEzZ79S-A1esAnJo1Kmzq80Jkc"
                .parse()
                .unwrap()],
            backers_to_remove: vec![],
        });
        let vrt = ManagerTelEvent::new(&pref, 1, event_type.clone())
            .to_message(SerializationFormats::JSON, SelfAddressing::Blake3_256)?;
        // Try to update backers of backerless state.
        let state = state.apply(&vrt);
        assert!(state.is_err());

        Ok(())
    }
}