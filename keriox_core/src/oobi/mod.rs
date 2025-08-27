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
    pub url: Url,
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
        Self { eid, scheme, url }
    }

    pub fn get_eid(&self) -> IdentifierPrefix {
        self.eid.clone()
    }

    pub fn get_scheme(&self) -> Scheme {
        self.scheme.clone()
    }

    pub fn get_url(&self) -> Url {
        self.url.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumString)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    #[strum(serialize = "http")]
    Http,
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
        #[error("Keri error")]
        Keri(#[from] crate::error::Error),

        #[error("DB error: {0}")]
        Db(String),

        #[error("Oobi parse error: {0}")]
        Parse(String),

        #[error("query error")]
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
        let oobi = r#"{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}"#;
        let _o: EndRole = serde_json::from_str(oobi).unwrap();

        let oobi = r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#;
        let _o: LocationScheme = serde_json::from_str(oobi).unwrap();

        Ok(())
    }
}
