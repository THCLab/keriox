use crate::error::Error;
use crate::event_message::EventTypeTag;
use crate::event_message::Typeable;
use crate::prefix::IdentifierPrefix;
use cesrox::payload::Payload;
use said::version::format::SerializationFormats;
use said::version::SerializationInfo;
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};
use serde_hex::{Compact, SerHex};

/// Receipt event is not a SAD. That's because TypedEvent wrapper is not used here.
/// It's digest field is digest of receipted event, not digest of receipt itself.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Receipt {
    #[serde(rename = "v")]
    pub serialization_info: SerializationInfo,

    #[serde(rename = "t")]
    pub event_type: EventTypeTag,

    /// Receipted Event Digest
    ///
    /// A Qualified Digest of the event which this receipt is made for
    /// (not the receipt message itself).
    #[serde(rename = "d")]
    pub receipted_event_digest: SelfAddressingIdentifier,

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
        receipted_event_digest: SelfAddressingIdentifier,
        prefix: IdentifierPrefix,
        sn: u64,
    ) -> Self {
        let mut receipt = Self {
            serialization_info: SerializationInfo::new_empty("KERI".to_string(), 1, 0, format),
            receipted_event_digest,
            prefix,
            sn,
            event_type: EventTypeTag::Rct,
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
