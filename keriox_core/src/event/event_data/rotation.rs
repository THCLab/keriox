use super::super::sections::{key_config::has_repeats, seal::*, KeyConfig, RotationWitnessConfig};
use crate::{
    database::rkyv_adapter::said_wrapper::SaidValue,
    error::Error,
    prefix::BasicPrefix,
    state::{check_keys, EventSemantics, IdentifierState, LastEstablishmentData, WitnessConfig},
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

    /// Configuration traits (`c`): REQUIRED in KERI 2.0 bodies, absent from
    /// KERI 1.0 ones.
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub config: Option<Vec<String>>,

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
            config: None,
            data,
        }
    }

    pub fn previous_event_hash(&self) -> &SelfAddressingIdentifier {
        &self.previous_event_hash.said
    }
}

impl EventSemantics for RotationEvent {
    fn apply_to(&self, state: IdentifierState) -> Result<IdentifierState, Error> {
        check_keys(
            self.key_config
                .public_keys
                .iter()
                .chain(&self.witness_config.graft),
        )?;
        self.key_config
            .check_current()
            .map_err(Error::SemanticError)?;
        self.key_config
            .next_keys_data
            .check_commitment()
            .map_err(Error::SemanticError)?;
        if has_repeats(&self.witness_config.prune) || has_repeats(&self.witness_config.graft) {
            return Err(Error::SemanticError(
                "the removed and the added witness lists must not repeat a witness".into(),
            ));
        }
        if state.current.verify_next(&self.key_config)? {
            // The removed witnesses go first, then the added ones are
            // appended, except those that are witnesses already.
            let mut witnesses = state
                .witness_config
                .witnesses
                .into_iter()
                .filter(|e| !self.witness_config.prune.contains(e))
                .collect::<Vec<BasicPrefix>>();
            for added in &self.witness_config.graft {
                if !witnesses.contains(added) {
                    witnesses.push(added.clone());
                }
            }
            let witness_config = WitnessConfig {
                tally: self.witness_config.tally.clone(),
                witnesses,
            };
            witness_config.check().map_err(Error::SemanticError)?;
            let last_est = LastEstablishmentData {
                sn: state.sn,
                digest: state.last_event_digest.clone(),
                br: self.witness_config.prune.clone(),
                ba: self.witness_config.graft.clone(),
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
