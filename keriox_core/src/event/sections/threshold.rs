use std::{fmt, str::FromStr};

use crate::error::Error;
use fraction::{Fraction, One, Zero};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum ThresholdError {
    #[error("Error parsing numerical value")]
    ParseIntError,
    #[error("Wrong threshold value. Should be fraction")]
    FractionExpected,
}

impl From<core::num::ParseIntError> for ThresholdError {
    fn from(_: core::num::ParseIntError) -> Self {
        ThresholdError::ParseIntError
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdFraction {
    fraction: Fraction,
}

impl ThresholdFraction {
    pub fn new(n: u64, d: u64) -> Self {
        Self {
            fraction: Fraction::new(n, d),
        }
    }
}

impl fmt::Display for ThresholdFraction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.fraction)
    }
}

impl FromStr for ThresholdFraction {
    type Err = ThresholdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let f: Vec<_> = s.split('/').collect();
        if f.len() > 2 {
            Err(ThresholdError::FractionExpected)
        } else if f.len() == 1 {
            let a = f[0].parse::<u64>()?;
            Ok(ThresholdFraction {
                fraction: Fraction::new(a, 1u64),
            })
        } else {
            let a = f[0].parse::<u64>()?;
            let b = f[1].parse::<u64>()?;
            Ok(ThresholdFraction {
                fraction: Fraction::new(a, b),
            })
        }
    }
}
impl<'de> Deserialize<'de> for ThresholdFraction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        FromStr::from_str(&s).map_err(de::Error::custom)
    }
}

impl Serialize for ThresholdFraction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum SignatureThreshold {
    #[serde(with = "SerHex::<Compact>")]
    Simple(u64),
    Weighted(WeightedThreshold),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
pub enum WeightedThreshold {
    Single(ThresholdClause),
    Multi(MultiClauses),
}

impl WeightedThreshold {
    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<bool, Error> {
        match self {
            WeightedThreshold::Single(clause) => clause.enough_signatures(0, sigs_indexes),
            WeightedThreshold::Multi(clauses) => clauses.enough_signatures(sigs_indexes),
        }
    }
}

impl SignatureThreshold {
    pub fn simple(t: u64) -> Self {
        Self::Simple(t)
    }

    pub fn single_weighted(fracs: Vec<(u64, u64)>) -> Self {
        Self::Weighted(WeightedThreshold::Single(ThresholdClause::new_from_tuples(
            fracs,
        )))
    }

    pub fn multi_weighted(fracs: Vec<Vec<(u64, u64)>>) -> Self {
        Self::Weighted(WeightedThreshold::Multi(MultiClauses::new_from_tuples(
            fracs,
        )))
    }

    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<bool, Error> {
        match self {
            SignatureThreshold::Simple(ref t) => Ok((sigs_indexes.len() as u64) >= *t),
            SignatureThreshold::Weighted(ref thresh) => thresh.enough_signatures(sigs_indexes),
        }
    }
}

impl Default for SignatureThreshold {
    fn default() -> Self {
        Self::Simple(1)
    }
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct ThresholdClause(Vec<ThresholdFraction>);

impl ThresholdClause {
    pub fn new(fracs: &[ThresholdFraction]) -> Self {
        Self(fracs.to_owned())
    }

    pub fn new_from_tuples(tuples: Vec<(u64, u64)>) -> Self {
        let clause = tuples
            .into_iter()
            .map(|(n, d)| ThresholdFraction::new(n, d))
            .collect();
        Self(clause)
    }

    pub fn length(&self) -> usize {
        self.0.len()
    }

    pub fn enough_signatures(
        &self,
        start_index: usize,
        sigs_indexes: &[usize],
    ) -> Result<bool, Error> {
        Ok(sigs_indexes
            .iter()
            .fold(Some(Zero::zero()), |acc: Option<Fraction>, sig_index| {
                if let (Some(element), Some(sum)) = (self.0.get(sig_index - start_index), acc) {
                    Some(sum + element.fraction)
                } else {
                    None
                }
            })
            .ok_or_else(|| Error::SemanticError("signature index out of bound".into()))?
            >= One::one())
    }
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq)]
pub struct MultiClauses(Vec<ThresholdClause>);

impl MultiClauses {
    pub fn new(fracs: Vec<Vec<ThresholdFraction>>) -> Self {
        let clauses = fracs
            .iter()
            .map(|clause| ThresholdClause::new(clause))
            .collect();

        Self(clauses)
    }

    pub fn new_from_tuples(fracs: Vec<Vec<(u64, u64)>>) -> Self {
        let wt = fracs
            .into_iter()
            .map(ThresholdClause::new_from_tuples)
            .collect();
        MultiClauses(wt)
    }

    pub fn length(&self) -> usize {
        self.0.iter().map(|l| l.length()).sum()
    }

    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<bool, Error> {
        Ok(self
            .0
            .iter()
            .fold(Ok((0, true)), |acc, clause| -> Result<_, Error> {
                let (start, enough) = acc?;
                let sigs: Vec<usize> = sigs_indexes
                    .iter()
                    .cloned()
                    .filter(|sig_index| {
                        sig_index >= &start && sig_index < &(start + clause.0.len())
                    })
                    .collect();
                Ok((
                    start + clause.0.len(),
                    enough && clause.enough_signatures(start, &sigs)?,
                ))
            })?
            .1)
    }
}

#[test]
fn test_enough_sigs() -> Result<(), Error> {
    // Threshold: [[1/1], [1/2, 1/2, 1/2], [1/2,1/2]]
    let wt = MultiClauses::new_from_tuples(vec![vec![(1, 1)], vec![(1, 2), (1, 2), (1, 2)]]);
    let sigs_indexes: Vec<_> = vec![0, 1, 2, 3];

    // All signatures.
    assert!(wt.enough_signatures(&sigs_indexes.clone())?);

    // Enough signatures.
    let enough = vec![
        sigs_indexes[0].clone(),
        sigs_indexes[1].clone(),
        sigs_indexes[3].clone(),
    ];
    assert!(wt.enough_signatures(&enough.clone())?);

    let not_enough = vec![sigs_indexes[0].clone()];
    assert!(!wt.enough_signatures(&not_enough.clone())?);

    Ok(())
}

#[test]
pub fn test_weighted_treshold_serialization() -> Result<(), Error> {
    let multi_threshold = r#"[["1"],["1/2","1/2","1/2"]]"#.to_string();
    let wt: WeightedThreshold = serde_json::from_str(&multi_threshold).unwrap();
    assert!(matches!(wt, WeightedThreshold::Multi(_)));
    // assert_eq!(serde_json::to_string(&wt).unwrap(), multi_threshold);
    assert_eq!(
        serde_json::to_string(&wt).unwrap(),
        r#"[["1"],["1/2","1/2","1/2"]]"#.to_string()
    );

    let single_threshold = r#"["1/2","1/2","1/2"]"#.to_string();
    let wt: WeightedThreshold = serde_json::from_str(&single_threshold).unwrap();
    assert!(matches!(wt, WeightedThreshold::Single(_)));
    assert_eq!(serde_json::to_string(&wt).unwrap(), single_threshold);
    Ok(())
}
