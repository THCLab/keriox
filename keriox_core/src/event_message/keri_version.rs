use std::fmt;

use said::version::{format::SerializationFormats, SerializationInfo};
use serde::{Deserialize, Serialize};

/// The KERI protocol version a message is written in, with the CESR code
/// tables its attachments use. Versions are named in the dotted-decimal
/// notation of the CESR specification ("Version String field"): `1.0` and
/// `2.0`, which is also how they are written in configuration and reported
/// on `GET /info`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum KeriVersion {
    /// KERI protocol 1.0: version string `KERI10JSON000000_` (`vv` = `10`,
    /// lowercase hex), with attachments in the CESR 1.0 code table
    /// (`-_AAABAA`, "Version 1.00"). The 1.x version string has no genus
    /// field; the 1.0 table is implied.
    #[default]
    V1_0,
    /// KERI protocol 2.0 on CESR genus 2.0: version string
    /// `KERICAACAAJSONAAAA.` (`Mmm` = `CAA`, protocol 2.0; `Ggg` = `CAA`,
    /// genus 2.0), with attachments in the CESR 2.0 code table
    /// (`-_AAACAA`, "Version 2.00").
    V2_0,
}

impl fmt::Display for KeriVersion {
    /// The protocol version, `1.0` or `2.0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            KeriVersion::V1_0 => "1.0",
            KeriVersion::V2_0 => "2.0",
        })
    }
}

impl Serialize for KeriVersion {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for KeriVersion {
    /// `1.0` or `2.0`, as a string or a number (a configuration file may
    /// write either). A bare `1` or `2` is refused: the version is always
    /// written major.minor.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = KeriVersion;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("the KERI protocol version 1.0 or 2.0")
            }

            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<KeriVersion, E> {
                text.parse().map_err(E::custom)
            }

            fn visit_f64<E: serde::de::Error>(self, number: f64) -> Result<KeriVersion, E> {
                if number == 1.0 {
                    Ok(KeriVersion::V1_0)
                } else if number == 2.0 {
                    Ok(KeriVersion::V2_0)
                } else {
                    Err(E::custom(UNKNOWN))
                }
            }

            fn visit_u64<E: serde::de::Error>(self, _: u64) -> Result<KeriVersion, E> {
                Err(E::custom(UNKNOWN))
            }

            fn visit_i64<E: serde::de::Error>(self, _: i64) -> Result<KeriVersion, E> {
                Err(E::custom(UNKNOWN))
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

const UNKNOWN: &str = "the KERI protocol version is written 1.0 or 2.0";

impl std::str::FromStr for KeriVersion {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        match text.trim() {
            "1.0" => Ok(KeriVersion::V1_0),
            "2.0" => Ok(KeriVersion::V2_0),
            _ => Err(UNKNOWN.to_string()),
        }
    }
}

impl KeriVersion {
    /// The CESR genus version of the code tables the attachments use,
    /// dotted-decimal: `1.0` or `2.0`.
    pub fn cesr_genus(self) -> &'static str {
        match self {
            KeriVersion::V1_0 => "1.0",
            KeriVersion::V2_0 => "2.0",
        }
    }

    /// The version string of an empty message in this version, to be
    /// filled with the message's size once it is serialized.
    pub fn serialization_info(self, format: SerializationFormats) -> SerializationInfo {
        match self {
            KeriVersion::V1_0 => SerializationInfo::new_empty("KERI".to_string(), 1, 0, format),
            KeriVersion::V2_0 => {
                let mut info = SerializationInfo::new_empty("KERI".to_string(), 2, 0, format);
                info.genus_version = Some((2, 0));
                info
            }
        }
    }

    /// The version a received message's version string names. Every minor
    /// version of a supported major is read by that major's rules, as minor
    /// versions stay backward compatible; any other major, or a 2.x message
    /// whose CESR genus is not 2.x, is refused.
    pub fn read(info: &SerializationInfo) -> Result<Self, String> {
        match (info.major_version, info.genus_version) {
            (1, None) => Ok(KeriVersion::V1_0),
            (2, Some((2, _))) => Ok(KeriVersion::V2_0),
            (2, genus) => Err(format!(
                "KERI protocol 2.{} on CESR genus {} is not supported",
                info.minor_version,
                genus.map_or("none".to_string(), |(major, minor)| format!(
                    "{major}.{minor}"
                ))
            )),
            (major, _) => Err(format!(
                "KERI protocol {major}.{} is not supported",
                info.minor_version
            )),
        }
    }

    /// The version of a message keriox has already read (see [`Self::read`])
    /// or written.
    pub fn of(info: &SerializationInfo) -> Self {
        if info.major_version >= 2 {
            KeriVersion::V2_0
        } else {
            KeriVersion::V1_0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_in_configuration() {
        for (written, version) in [
            ("\"1.0\"", KeriVersion::V1_0),
            ("\"2.0\"", KeriVersion::V2_0),
            ("\" 2.0 \"", KeriVersion::V2_0),
            ("1.0", KeriVersion::V1_0),
            ("2.0", KeriVersion::V2_0),
        ] {
            assert_eq!(
                serde_json::from_str::<KeriVersion>(written).unwrap(),
                version
            );
        }
        for refused in ["1", "2", "\"2\"", "3.0", "\"2.1\""] {
            assert!(
                serde_json::from_str::<KeriVersion>(refused).is_err(),
                "{refused}"
            );
        }
        assert_eq!(
            serde_json::to_string(&KeriVersion::V2_0).unwrap(),
            "\"2.0\""
        );
        assert_eq!(KeriVersion::V1_0.to_string(), "1.0");
        assert_eq!(KeriVersion::V2_0.cesr_genus(), "2.0");
    }

    #[test]
    fn version_strings() {
        assert_eq!(
            KeriVersion::V1_0
                .serialization_info(SerializationFormats::JSON)
                .to_str(),
            "KERI10JSON000000_"
        );
        assert_eq!(
            KeriVersion::V2_0
                .serialization_info(SerializationFormats::JSON)
                .to_str(),
            "KERICAACAAJSONAAAA."
        );
        for version in [KeriVersion::V1_0, KeriVersion::V2_0] {
            let info = version.serialization_info(SerializationFormats::JSON);
            assert_eq!(KeriVersion::of(&info), version);
            assert_eq!(KeriVersion::read(&info), Ok(version));
        }
    }

    #[test]
    fn only_supported_majors_are_read() {
        let json = SerializationFormats::JSON;
        let minor = |major, minor, genus| {
            let mut info = SerializationInfo::new_empty("KERI".to_string(), major, minor, json);
            info.genus_version = genus;
            info
        };
        assert_eq!(KeriVersion::read(&minor(1, 1, None)), Ok(KeriVersion::V1_0));
        assert_eq!(
            KeriVersion::read(&minor(2, 1, Some((2, 0)))),
            Ok(KeriVersion::V2_0)
        );
        assert!(KeriVersion::read(&minor(3, 0, Some((3, 0)))).is_err());
        assert!(KeriVersion::read(&minor(2, 0, Some((1, 0)))).is_err());
        assert!(KeriVersion::read(&minor(2, 0, None)).is_err());
    }
}
