use super::super::sections::{seal::*, KeyConfig, WitnessConfig};
use crate::{
    error::Error,
    prefix::{BasicPrefix, SelfAddressingPrefix},
    state::{EventSemantics, IdentifierState, LastEstablishmentData},
};
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describes the rotation (rot) event data
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct RotationEvent {
    #[serde(rename = "p")]
    pub previous_event_hash: SelfAddressingPrefix,

    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: WitnessConfig,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl EventSemantics for RotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        if state.current.verify_next(&self.key_config) {
            // witness rotation processing
            let witnesses =
                if !self.witness_config.prune.is_empty() || !self.witness_config.graft.is_empty() {
                    let mut prunned = state
                        .witnesses
                        .into_iter()
                        .filter(|e| !self.witness_config.prune.contains(e))
                        .collect::<Vec<BasicPrefix>>();
                    prunned.append(&mut self.witness_config.graft.clone());
                    prunned
                } else {
                    state.witnesses.clone()
                };
            let last_est = LastEstablishmentData {
                sn: state.sn,
                digest: state.last_event_digest.clone(),
                br: self.witness_config.graft.clone(),
                ba: self.witness_config.prune.clone(),
            };

            Ok(IdentifierState {
                current: self.key_config.clone(),
                tally: self.witness_config.tally,
                witnesses,
                last_est,
                ..state
            })
        } else {
            Err(Error::SemanticError("Incorrect Key Config binding".into()))
        }
    }
}
