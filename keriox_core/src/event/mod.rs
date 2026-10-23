use crate::event_message::msg::KeriEvent;
use crate::event_message::{keri_version::KeriVersion, EventTypeTag, Typeable};
use crate::prefix::IdentifierPrefix;
use crate::state::IdentifierState;
use said::derivation::HashFunction;
use said::version::format::SerializationFormats;
use serde::{Deserialize, Serialize};
pub mod event_data;
pub mod receipt;
pub mod sections;
use self::event_data::EventData;
use crate::error::Error;
use crate::state::EventSemantics;
use serde_hex::{Compact, SerHex};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct KeyEvent {
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,

    #[serde(flatten)]
    pub event_data: EventData,
}

impl KeyEvent {
    pub fn new(prefix: IdentifierPrefix, sn: u64, event_data: EventData) -> Self {
        KeyEvent {
            prefix,
            sn,
            event_data,
        }
    }

    /// The event as a message in `version`. A KERI 2.0 rotation carries
    /// the configuration traits field `c`, empty unless set.
    pub fn to_message(
        mut self,
        version: KeriVersion,
        format: SerializationFormats,
        derivation: HashFunction,
    ) -> Result<KeriEvent<KeyEvent>, Error> {
        if let (KeriVersion::V2_0, EventData::Rot(rot) | EventData::Drt(rot)) =
            (version, &mut self.event_data)
        {
            rot.config.get_or_insert_with(Vec::new);
        }
        match (&self.prefix, self.event_data.clone()) {
            (IdentifierPrefix::SelfAddressing(_), EventData::Icp(icp)) => {
                icp.incept_self_addressing(version, derivation.clone(), format)
            }
            (IdentifierPrefix::SelfAddressing(_), EventData::Dip(dip)) => {
                dip.incept_self_addressing(version, derivation.clone(), format)
            }
            _ => Ok(KeriEvent::new(version, format, derivation, self)),
        }
    }
}

impl Typeable for KeyEvent {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        self.event_data.get_type()
    }
}

impl EventSemantics for KeyEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        match self.event_data {
            EventData::Icp(_) | EventData::Dip(_) => {
                // ICP events require the state to be uninitialized
                if state.prefix != IdentifierPrefix::default() {
                    return Err(Error::EventDuplicateError);
                }
                if self.sn != 0 {
                    return Err(Error::SemanticError("SN is not correct".to_string()));
                }
            }
            _ => {
                // An event of an identifier whose inception has not been seen
                // yet may still become valid once the inception arrives.
                if state.prefix == IdentifierPrefix::default() {
                    return Err(Error::EventOutOfOrderError);
                }
                // prefix must equal.
                if self.prefix != state.prefix {
                    return Err(Error::SemanticError("Prefix does not match".to_string()));
                // sn must be incremented
                // TODO recovery will break this rule when we implement it
                } else if self.sn < state.sn + 1 {
                    return Err(Error::EventDuplicateError);
                // A log without next keys (non-transferable or abandoned) is
                // final, so a later event is refused rather than kept
                // waiting as out of order.
                } else if !state.is_transferable() {
                    return Err(state.final_log_error());
                } else if self.sn > state.sn + 1 {
                    return Err(Error::EventOutOfOrderError);
                }
            }
        };
        self.event_data.apply_to(IdentifierState {
            sn: self.sn,
            prefix: self.prefix.clone(),
            ..state
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn ser_der() -> Result<(), serde_json::Error> {
        let event_str = "{
  \"i\": \"DHq5YqaL6L48pf0fu7IUhL0JRaU2_RxFP0AL43wYn148\",
  \"s\": \"0\",
  \"t\": \"icp\",
  \"kt\": \"2\",
  \"k\":
  [
    \"BGoNZsa88VrTkep6HQt27fTh-4HA8tr54sHON1vWl6FE\",
    \"BMtr54sHON1vWVrTkep6H-4HAl6FEQt27fThWoNZsa88\",
    \"BFrTkep6HHA8tr54sHON1Qt27fThWoNZsa88-4vWl6FE\"
  ],
  \"nt\": \"3\",
  \"n\" : 
    [
      \"EDNZH3ULvYawyZ-i0d8JZU6JR2nmAoAfSVPzhzS6b5CM\",
      \"EHmwyZdi0d8JZAoTNZYAfSVPzhzaU6JR2H3ULvS6b5CM\",
      \"EDNZH3ULvS6bYAfSVPzhzaU6JR2nmwyZfi0d8JZ5s8bk\"
    ],
  \"bt\": \"2\",
  \"b\":
  [
    \"DFrTkep6H-Qt27fThWoNZsa884HA8tr54sHON1vWl6FE\",
    \"DHON1vWl6FEQt27fThWoNZsa88VrTkep6H-4HA8tr54s\",
    \"DDhWoNZsa88VrTkeQt27fp6H-4HA8tr54sHON1vWl6FE\"
  ],
  \"c\": [],
  \"a\": []
}";

        let event: KeyEvent = serde_json::from_str(event_str)?;

        print!("\n{}\n", serde_json::to_string(&event)?);

        Ok(())
    }
}
