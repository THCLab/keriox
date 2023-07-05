use serde::{Deserialize, Serialize};

use crate::prefix::IdentifierPrefix;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryArgsMbx {
    /// Controller's currently used indentifier
    pub pre: IdentifierPrefix,
    /// Types of mail to query and their minimum serial number
    pub topics: QueryTopics,
    /// Identifier to be queried
    pub i: IdentifierPrefix,
    /// To which witness given query message reply will be sent
    pub src: IdentifierPrefix,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct QueryTopics {
    #[serde(rename = "/receipt")]
    pub receipt: usize,
    #[serde(rename = "/replay")]
    pub replay: usize,
    #[serde(rename = "/reply")]
    pub reply: usize,
    #[serde(rename = "/multisig")]
    pub multisig: usize,
    #[serde(rename = "/credential")]
    pub credential: usize,
    #[serde(rename = "/delegate")]
    pub delegate: usize,
}
