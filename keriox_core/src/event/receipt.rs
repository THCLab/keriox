use crate::error::Error;
use crate::event_message::EventTypeTag;
use crate::event_message::Typeable;
use crate::prefix::IdentifierPrefix;
use cesrox::payload::Payload;
use sai::SelfAddressingPrefix;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};
use version::serialization_info::SerializationFormats;
use version::serialization_info::SerializationInfo;

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
        let mut receipt = Self {
            serialization_info: SerializationInfo::new_empty("KERI".to_string(), format),
            receipted_event_digest,
            prefix,
            sn,
        };
        let len = receipt.encode().unwrap().len();
        receipt.serialization_info.size = len;
        receipt
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        Ok(self.serialization_info.serialize(&self).unwrap())
    }
}

impl From<Receipt> for Payload {
    fn from(pd: Receipt) -> Self {
        match pd.serialization_info.kind {
            SerializationFormats::JSON => Payload::JSON(pd.encode().unwrap()),
            SerializationFormats::MGPK => Payload::MGPK(pd.encode().unwrap()),
            SerializationFormats::CBOR => Payload::CBOR(pd.encode().unwrap()),
        }
    }
}

impl Typeable for Receipt {
    type TypeTag = EventTypeTag;
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Rct
    }
}
