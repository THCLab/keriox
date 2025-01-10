use crate::{prefix::BasicPrefix, state::WitnessConfig};
use serde::{Deserialize, Serialize};

pub mod key_config;
pub mod seal;
pub mod threshold;

pub use key_config::KeyConfig;

use self::threshold::SignatureThreshold;
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
pub struct RotationWitnessConfig {
    #[serde(rename = "bt")]
    pub tally: SignatureThreshold,

    #[serde(rename = "br")]
    pub prune: Vec<BasicPrefix>,

    #[serde(rename = "ba")]
    pub graft: Vec<BasicPrefix>,
}

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
pub struct InceptionWitnessConfig {
    #[serde(rename = "bt")]
    pub tally: SignatureThreshold,

    #[serde(rename = "b")]
    pub initial_witnesses: Vec<BasicPrefix>,
}

impl Default for InceptionWitnessConfig {
    fn default() -> Self {
        Self {
            tally: SignatureThreshold::Simple(0),
            initial_witnesses: Default::default(),
        }
    }
}

impl From<InceptionWitnessConfig> for WitnessConfig {
    fn from(iwc: InceptionWitnessConfig) -> Self {
        Self {
            tally: iwc.tally,
            witnesses: iwc.initial_witnesses,
        }
    }
}

impl Default for RotationWitnessConfig {
    fn default() -> Self {
        Self {
            tally: SignatureThreshold::Simple(0),
            prune: Default::default(),
            graft: Default::default(),
        }
    }
}
