//! Field maps of routed messages whose content keriox does not model: the
//! `q` and `a` blocks of a route it does not serve. They keep their fields
//! in the order they were read in, so a message is written back byte for
//! byte, as its signatures and SAID require.

use std::fmt;

use serde::{
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Deserializer, Serialize, Serializer,
};

/// A field map, in its fields' order.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FieldMap(pub Vec<(String, FieldValue)>);

/// A value in a field map.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Null,
    Bool(bool),
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    List(Vec<FieldValue>),
    Map(FieldMap),
}

impl FieldMap {
    /// The value of the field `label`, if the map has it.
    pub fn get(&self, label: &str) -> Option<&FieldValue> {
        self.0
            .iter()
            .find_map(|(name, value)| (name == label).then_some(value))
    }
}

impl Serialize for FieldMap {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (label, value) in &self.0 {
            map.serialize_entry(label, value)?;
        }
        map.end()
    }
}

impl Serialize for FieldValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            FieldValue::Null => serializer.serialize_unit(),
            FieldValue::Bool(value) => serializer.serialize_bool(*value),
            FieldValue::Unsigned(value) => serializer.serialize_u64(*value),
            FieldValue::Signed(value) => serializer.serialize_i64(*value),
            FieldValue::Float(value) => serializer.serialize_f64(*value),
            FieldValue::String(value) => serializer.serialize_str(value),
            FieldValue::Bytes(value) => serializer.serialize_bytes(value),
            FieldValue::List(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(value)?;
                }
                seq.end()
            }
            FieldValue::Map(map) => map.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for FieldMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match FieldValue::deserialize(deserializer)? {
            FieldValue::Map(map) => Ok(map),
            other => Err(de::Error::custom(format!(
                "expected a field map, got {other:?}"
            ))),
        }
    }
}

impl<'de> Deserialize<'de> for FieldValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(FieldValueVisitor)
    }
}

struct FieldValueVisitor;

impl<'de> Visitor<'de> for FieldValueVisitor {
    type Value = FieldValue;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a field map value")
    }

    fn visit_unit<E>(self) -> Result<FieldValue, E> {
        Ok(FieldValue::Null)
    }

    fn visit_none<E>(self) -> Result<FieldValue, E> {
        Ok(FieldValue::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<FieldValue, D::Error> {
        FieldValue::deserialize(d)
    }

    fn visit_bool<E>(self, value: bool) -> Result<FieldValue, E> {
        Ok(FieldValue::Bool(value))
    }

    fn visit_u64<E>(self, value: u64) -> Result<FieldValue, E> {
        Ok(FieldValue::Unsigned(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<FieldValue, E> {
        // Non-negative integers are read as unsigned whatever the decoder
        // reports, so they are written back the same.
        Ok(u64::try_from(value)
            .map(FieldValue::Unsigned)
            .unwrap_or(FieldValue::Signed(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<FieldValue, E> {
        Ok(FieldValue::Float(value))
    }

    fn visit_str<E>(self, value: &str) -> Result<FieldValue, E> {
        Ok(FieldValue::String(value.to_string()))
    }

    fn visit_string<E>(self, value: String) -> Result<FieldValue, E> {
        Ok(FieldValue::String(value))
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<FieldValue, E> {
        Ok(FieldValue::Bytes(value.to_vec()))
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<FieldValue, E> {
        Ok(FieldValue::Bytes(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<FieldValue, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = seq.next_element()? {
            values.push(value);
        }
        Ok(FieldValue::List(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<FieldValue, A::Error> {
        let mut fields: Vec<(String, FieldValue)> = Vec::new();
        while let Some((label, value)) = map.next_entry::<String, FieldValue>()? {
            if fields.iter().any(|(seen, _)| seen == &label) {
                return Err(de::Error::custom(format!("field {label} appears twice")));
            }
            fields.push((label, value));
        }
        Ok(FieldValue::Map(FieldMap(fields)))
    }
}

#[cfg(test)]
mod tests {
    use super::FieldMap;

    /// A field map is written back in the order it was read in, numbers and
    /// nesting included, in JSON, CBOR and MessagePack.
    #[test]
    fn a_field_map_keeps_its_order() {
        let json = r#"{"zeta":"last first","action":"buy","price":300000.0,"count":3,"debt":-2,"ok":true,"none":null,"list":[1,"two",{"b":1,"a":2}]}"#;
        let map: FieldMap = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&map).unwrap(), json);

        let cbor = serde_cbor::to_vec(&map).unwrap();
        let from_cbor: FieldMap = serde_cbor::from_slice(&cbor).unwrap();
        assert_eq!(serde_cbor::to_vec(&from_cbor).unwrap(), cbor);
        assert_eq!(from_cbor, map);

        let mgpk = rmp_serde::to_vec(&map).unwrap();
        let from_mgpk: FieldMap = rmp_serde::from_slice(&mgpk).unwrap();
        assert_eq!(rmp_serde::to_vec(&from_mgpk).unwrap(), mgpk);
    }

    #[test]
    fn a_field_map_with_a_repeated_label_is_refused() {
        assert!(serde_json::from_str::<FieldMap>(r#"{"a":1,"a":2}"#).is_err());
        assert!(serde_json::from_str::<FieldMap>(r#"[1,2]"#).is_err());
    }
}
