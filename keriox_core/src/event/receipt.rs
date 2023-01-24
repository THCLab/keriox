use crate::error::Error;
use crate::event_message::Digestible;
use crate::event_message::EventTypeTag;
use crate::event_message::Typeable;
use crate::event_message::msg::KeriEvent;
use crate::prefix::IdentifierPrefix;
use crate::sai::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
use version::serialization_info::SerializationFormats;
use version::serialization_info::SerializationInfo;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for
    /// (not the receipt message itself).
    #[serde(rename = "d", skip_serializing)]
    pub receipted_event_digest: SelfAddressingPrefix,

    /// Receipted Event identifier
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    /// Receipted Event sn
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,
}

// impl Receipt {
//     pub fn to_message(self, format: SerializationFormats) -> Result<KeriEvent<Receipt>, Error> {
//        KeriEvent::new(format, derivation, self)
//     }
// }

impl Typeable for Receipt {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Rct
    }
}

impl Digestible for Receipt {
    fn get_digest(&self) -> SelfAddressingPrefix {
        self.receipted_event_digest.clone()
    }
}
