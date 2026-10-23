use said::version::{format::SerializationFormats, SerializationInfo};
use serde::{Deserialize, Serialize};

/// The KERI protocol version a message is written in. It sets the
/// message's version string; KERI 2.0 messages also carry their attachments
/// in CESR 2.0. In configuration it is written `1` or `2`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KeriVersion {
    /// KERI 1.0: `KERI10JSON000000_`.
    #[default]
    V1,
    /// KERI 2.0 (genus 2.00): `KERICAACAAJSONAAAA.`.
    V2,
}

impl Serialize for KeriVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u8(match self {
            KeriVersion::V1 => 1,
            KeriVersion::V2 => 2,
        })
    }
}

impl<'de> Deserialize<'de> for KeriVersion {
    /// `1` or `2`, as a number or a string (configuration files and
    /// environment variables give either).
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Written {
            Number(u64),
            Text(String),
        }
        match Written::deserialize(deserializer)? {
            Written::Number(1) => Ok(KeriVersion::V1),
            Written::Number(2) => Ok(KeriVersion::V2),
            Written::Text(text) if text.trim() == "1" => Ok(KeriVersion::V1),
            Written::Text(text) if text.trim() == "2" => Ok(KeriVersion::V2),
            _ => Err(serde::de::Error::custom("the KERI version is 1 or 2")),
        }
    }
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
    fn written_in_configuration() {
        for (written, version) in [
            ("1", KeriVersion::V1),
            ("2", KeriVersion::V2),
            ("\"2\"", KeriVersion::V2),
        ] {
            assert_eq!(
                serde_json::from_str::<KeriVersion>(written).unwrap(),
                version
            );
        }
        assert!(serde_json::from_str::<KeriVersion>("3").is_err());
        assert_eq!(serde_json::to_string(&KeriVersion::V2).unwrap(), "2");
    }

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
