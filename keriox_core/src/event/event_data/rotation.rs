use super::super::sections::{seal::*, KeyConfig, RotationWitnessConfig};
use crate::{
    database::rkyv_adapter::said_wrapper::SaidValue,
    error::Error,
    prefix::BasicPrefix,
    state::{EventSemantics, IdentifierState, LastEstablishmentData, WitnessConfig},
};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

/// Rotation Event
///
/// Describes the rotation (rot) event data
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct RotationEvent {
    #[serde(rename = "p")]
    previous_event_hash: SaidValue,

    #[serde(flatten)]
    pub key_config: KeyConfig,

    #[serde(flatten)]
    pub witness_config: RotationWitnessConfig,

    #[serde(rename = "a")]
    pub data: Vec<Seal>,
}

impl RotationEvent {
    pub fn new(
        previous_event_hash: SelfAddressingIdentifier,
        kc: KeyConfig,
        witness_config: RotationWitnessConfig,
        data: Vec<Seal>,
    ) -> Self {
        Self {
            previous_event_hash: previous_event_hash.into(),
            key_config: kc,
            witness_config,
            data,
        }
    }

    pub fn previous_event_hash(&self) -> &SelfAddressingIdentifier {
        &self.previous_event_hash.said
    }
}

impl EventSemantics for RotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        if state.current.verify_next(&self.key_config)? {
            // witness rotation processing
            let witnesses =
                if !self.witness_config.prune.is_empty() || !self.witness_config.graft.is_empty() {
                    let mut prunned = state
                        .witness_config
                        .witnesses
                        .into_iter()
                        .filter(|e| !self.witness_config.prune.contains(e))
                        .collect::<Vec<BasicPrefix>>();
                    prunned.append(&mut self.witness_config.graft.clone());
                    prunned
                } else {
                    state.witness_config.witnesses.clone()
                };
            let witness_config = WitnessConfig {
                tally: self.witness_config.tally.clone(),
                witnesses,
            };
            let last_est = LastEstablishmentData {
                sn: state.sn,
                digest: state.last_event_digest.clone(),
                br: self.witness_config.graft.clone(),
                ba: self.witness_config.prune.clone(),
            };

            Ok(IdentifierState {
                current: self.key_config.clone(),
                witness_config,
                last_est,
                ..state
            })
        } else {
            Err(Error::SemanticError("Incorrect Key Config binding".into()))
        }
    }
}
