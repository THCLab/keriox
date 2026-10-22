use serde::{Deserialize, Serialize};
use strum_macros::EnumString;
use url::Url;

use crate::prefix::IdentifierPrefix;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(untagged)]
pub enum Oobi {
    Location(LocationScheme),
    EndRole(EndRole),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LocationScheme {
    pub eid: IdentifierPrefix,
    pub scheme: Scheme,
    /// `None` nullifies the location: the KERI specification writes it as
    /// the empty string.
    #[serde(with = "empty_url_as_none")]
    pub url: Option<Url>,
}

mod empty_url_as_none {
    use serde::{Deserialize, Deserializer, Serializer};
    use url::Url;

    pub fn serialize<S: Serializer>(url: &Option<Url>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(url.as_ref().map_or("", |url| url.as_str()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Url>, D::Error> {
        let url = String::deserialize(d)?;
        if url.is_empty() {
            Ok(None)
        } else {
            Url::parse(&url).map(Some).map_err(serde::de::Error::custom)
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EndRole {
    /// Controller ID
    pub cid: IdentifierPrefix,

    pub role: Role,

    /// Endpoint provider ID
    pub eid: IdentifierPrefix,
}

impl LocationScheme {
    pub fn new(eid: IdentifierPrefix, scheme: Scheme, url: Url) -> Self {
        Self {
            eid,
            scheme,
            url: Some(url),
        }
    }

    /// A location that withdraws the endpoint's earlier location for
    /// `scheme`.
    pub fn nullify(eid: IdentifierPrefix, scheme: Scheme) -> Self {
        Self {
            eid,
            scheme,
            url: None,
        }
    }

    pub fn get_eid(&self) -> IdentifierPrefix {
        self.eid.clone()
    }

    pub fn get_scheme(&self) -> Scheme {
        self.scheme.clone()
    }

    /// The endpoint's url, or `None` for a nullified location.
    pub fn get_url(&self) -> Option<Url> {
        self.url.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumString)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[strum(serialize = "http")]
    Http,
    #[strum(serialize = "https")]
    Https,
    #[strum(serialize = "tcp")]
    Tcp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumString)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[strum(serialize = "controller")]
    Controller,
    #[strum(serialize = "witness")]
    Witness,
    #[strum(serialize = "watcher")]
    Watcher,
    #[strum(serialize = "messagebox")]
    Messagebox,
}

pub mod error {
    use serde::{Deserialize, Serialize};
    use thiserror::Error;

    #[derive(Error, Debug, Serialize, Deserialize)]
    pub enum OobiError {
        #[error("Keri error: {0}")]
        Keri(#[from] crate::error::Error),

        #[error("DB error: {0}")]
        Db(String),

        #[error("Oobi parse error: {0}")]
        Parse(String),

        #[error("query error: {0}")]
        Query(#[from] crate::query::QueryError),

        #[error("signer ID mismatch")]
        SignerMismatch,

        #[error("invalid message type")]
        InvalidMessageType,
    }
}

#[cfg(test)]
mod tests {
    use super::{EndRole, LocationScheme};
    use crate::error::Error;

    #[test]
    fn test_oobi_deserialize() -> Result<(), Error> {
        let oobi = r#"{"cid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}"#;
        let _o: EndRole = serde_json::from_str(oobi).unwrap();

        let oobi = r#"{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#;
        let _o: LocationScheme = serde_json::from_str(oobi).unwrap();

        Ok(())
    }
}
