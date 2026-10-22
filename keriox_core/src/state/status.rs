use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

use super::IdentifierState;
use crate::{
    event::sections::threshold::SignatureThreshold,
    prefix::{BasicPrefix, IdentifierPrefix},
};

/// What a witness or watcher knows about an identifier, as served on its
/// public `GET /identifiers/{aid}/state` endpoint.
///
/// It is a hint, not proof: anyone who must rely on the answer verifies the
/// key event log itself, as obtained through an authenticated query.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct IdentifierStatus {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub last_event_said: SelfAddressingIdentifier,
    /// Whether the identifier can still rotate. When not, its key event log
    /// is final: it was abandoned, or incepted non-transferable.
    pub transferable: bool,
    /// The rotation that abandoned the identifier, if it is abandoned.
    pub abandoned: Option<Abandonment>,
    pub witnesses: Vec<BasicPrefix>,
    pub witness_threshold: SignatureThreshold,
}

/// The rotation that committed to no next keys.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Abandonment {
    pub sn: u64,
    pub said: SelfAddressingIdentifier,
}

impl From<&IdentifierState> for IdentifierStatus {
    fn from(state: &IdentifierState) -> Self {
        Self {
            prefix: state.prefix.clone(),
            sn: state.sn,
            last_event_said: state.last_event_digest.said.clone(),
            transferable: state.is_transferable(),
            abandoned: state
                .abandonment()
                .map(|(sn, said)| Abandonment { sn, said }),
            witnesses: state.witness_config.witnesses.clone(),
            witness_threshold: state.witness_config.tally.clone(),
        }
    }
}
