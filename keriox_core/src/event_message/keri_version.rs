use said::version::{format::SerializationFormats, SerializationInfo};
use serde::{Deserialize, Serialize};

/// The KERI protocol version a message is written in. It sets the
/// message's version string; KERI 2.0 messages also carry their attachments
/// in CESR 2.0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KeriVersion {
    /// KERI 1.0: `KERI10JSON000000_`.
    #[default]
    #[serde(rename = "1")]
    V1,
    /// KERI 2.0 (genus 2.00): `KERICAACAAJSONAAAA.`.
    #[serde(rename = "2")]
    V2,
}

impl KeriVersion {
    /// The version string of an empty message in this version, to be
    /// filled with the message's size once it is serialized.
    pub fn serialization_info(self, format: SerializationFormats) -> SerializationInfo {
        match self {
            KeriVersion::V1 => SerializationInfo::new_empty("KERI".to_string(), 1, 0, format),
            KeriVersion::V2 => {
                let mut info = SerializationInfo::new_empty("KERI".to_string(), 2, 0, format);
                info.genus_version = Some((2, 0));
                info
            }
        }
    }

    /// The version a message's version string names.
    pub fn of(info: &SerializationInfo) -> Self {
        if info.major_version >= 2 {
            KeriVersion::V2
        } else {
            KeriVersion::V1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_strings() {
        assert_eq!(
            KeriVersion::V1
                .serialization_info(SerializationFormats::JSON)
                .to_str(),
            "KERI10JSON000000_"
        );
        assert_eq!(
            KeriVersion::V2
                .serialization_info(SerializationFormats::JSON)
                .to_str(),
            "KERICAACAAJSONAAAA."
        );
        for version in [KeriVersion::V1, KeriVersion::V2] {
            assert_eq!(
                KeriVersion::of(&version.serialization_info(SerializationFormats::JSON)),
                version
            );
        }
    }
}
