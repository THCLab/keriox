use crate::error::Error;
use crate::event_message::msg::KeriEvent;
use crate::event_message::Digestible;
use crate::event_message::EventTypeTag;
use crate::event_message::Typeable;
use crate::prefix::IdentifierPrefix;
use crate::sai::SelfAddressingPrefix;
use cesrox::payload::Payload;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
use version::serialization_info;
use version::serialization_info::SerializationFormats;
use version::serialization_info::SerializationInfo;
use version::Versional;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,
    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for
    /// (not the receipt message itself).
    #[serde(rename = "d")]
    pub receipted_event_digest: SelfAddressingPrefix,

    /// Receipted Event identifier
    #[serde(rename = "i")]
    pub prefix: IdentifierPrefix,

    /// Receipted Event sn
    #[serde(rename = "s", with = "SerHex::<Compact>")]
    pub sn: u64,
}

impl Receipt {
    pub fn new(
        format: SerializationFormats,
        receipted_event_digest: SelfAddressingPrefix,
        prefix: IdentifierPrefix,
        sn: u64,
    ) -> Self {
        let mut serialization_info = SerializationInfo::new_empty(['K', 'E', 'R', 'I'], format);
        let mut receipt = Self {
            serialization_info,
            receipted_event_digest,
            prefix,
            sn,
        };
        let len = Versional::serialize(&receipt).unwrap().len();
        serialization_info.size = len;
        receipt.serialization_info = serialization_info;
        receipt
    }
}

impl From<Receipt> for Payload {
    fn from(pd: Receipt) -> Self {
        match pd.serialization_info.kind {
            SerializationFormats::JSON => Payload::JSON(Versional::serialize(&pd).unwrap()),
            SerializationFormats::MGPK => Payload::MGPK(Versional::serialize(&pd).unwrap()),
            SerializationFormats::CBOR => Payload::CBOR(Versional::serialize(&pd).unwrap()),
        }
    }
}

impl Versional for Receipt {
    fn get_version_str(&self) -> SerializationInfo {
        self.serialization_info
    }
}

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
