use std::{fmt, str::FromStr};

use fraction::{Fraction, One, Zero};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use serde_hex::{Compact, SerHex};

use super::key_config::SignatureError;

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

#[derive(Debug, Clone, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub struct ThresholdFraction {
    #[rkyv(with = rkyv_serialization::FractionDef)]
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
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub enum SignatureThreshold {
    #[serde(with = "SerHex::<Compact>")]
    Simple(u64),
    Weighted(WeightedThreshold),
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub enum WeightedThreshold {
    Single(ThresholdClause),
    Multi(MultiClauses),
    // Nested thresholds come last, and are vectors like the others, so the
    // stored (rkyv) layout of existing thresholds does not change.
    /// One clause with groups of keys counted as one weight.
    NestedSingle(NestedClause),
    /// Clauses with groups of keys counted as one weight, all of which
    /// must be met.
    NestedMulti(NestedClauses),
}

impl WeightedThreshold {
    /// Number of weights, i.e. of keys the threshold speaks about.
    pub fn length(&self) -> usize {
        match self {
            WeightedThreshold::Single(clause) => clause.length(),
            WeightedThreshold::Multi(clauses) => clauses.length(),
            WeightedThreshold::NestedSingle(clause) => clause.length(),
            WeightedThreshold::NestedMulti(clauses) => clauses.length(),
        }
    }

    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<(), SignatureError> {
        let sigs_indexes = distinct(sigs_indexes);
        match self {
            WeightedThreshold::Single(clause) => clause.enough_signatures(0, &sigs_indexes),
            WeightedThreshold::Multi(clauses) => clauses.enough_signatures(&sigs_indexes),
            WeightedThreshold::NestedSingle(clause) => clause
                .met(0, &sigs_indexes)
                .then_some(())
                .ok_or(SignatureError::NotEnoughSigsError),
            WeightedThreshold::NestedMulti(clauses) => clauses
                .met(&sigs_indexes)
                .then_some(())
                .ok_or(SignatureError::NotEnoughSigsError),
        }
    }
}

/// The indexes without repeats, in ascending order.
fn distinct(indexes: &[usize]) -> Vec<usize> {
    let mut indexes = indexes.to_vec();
    indexes.sort_unstable();
    indexes.dedup();
    indexes
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

    /// Checks that the threshold fits a list of `keys` keys or key digests,
    /// as the KERI specification requires: an integer threshold M of N may
    /// not need more than the N keys, and a fractionally weighted threshold
    /// has exactly one weight per key.
    pub fn check_fits(&self, keys: usize) -> Result<(), String> {
        match self {
            SignatureThreshold::Simple(t) if *t as usize > keys => {
                Err(format!("threshold {t} needs more than the {keys} keys"))
            }
            SignatureThreshold::Weighted(weighted) if weighted.length() != keys => Err(format!(
                "threshold lists {} weights for {keys} keys",
                weighted.length()
            )),
            _ => Ok(()),
        }
    }

    /// Whether signatures by the keys at `sigs_indexes` satisfy the
    /// threshold. Each key counts once however often its index appears:
    /// a threshold is M of the N keys of a key set.
    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<(), SignatureError> {
        match self {
            SignatureThreshold::Simple(ref t) => {
                if (distinct(sigs_indexes).len() as u64) >= *t {
                    Ok(())
                } else {
                    Err(SignatureError::NotEnoughSigsError)
                }
            }
            SignatureThreshold::Weighted(ref thresh) => thresh.enough_signatures(sigs_indexes),
        }
    }
}

impl Default for SignatureThreshold {
    fn default() -> Self {
        Self::Simple(1)
    }
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
    ) -> Result<(), SignatureError> {
        (sigs_indexes
            .iter()
            .fold(Some(Zero::zero()), |acc: Option<Fraction>, sig_index| {
                if let (Some(element), Some(sum)) = (self.0.get(sig_index - start_index), acc) {
                    Some(sum + element.fraction)
                } else {
                    None
                }
            })
            .ok_or_else(|| SignatureError::MissingIndex)?
            >= One::one())
        .then(|| ())
        .ok_or(SignatureError::NotEnoughSigsError)
    }
}

#[derive(
    Deserialize,
    Serialize,
    Debug,
    Clone,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]

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

    pub fn enough_signatures(&self, sigs_indexes: &[usize]) -> Result<(), SignatureError> {
        self.0
            .iter()
            .fold(Ok((0, true)), |acc, clause| -> Result<_, SignatureError> {
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
                    enough && clause.enough_signatures(start, &sigs).is_ok(),
                ))
            })?
            .1
            .then(|| ())
            .ok_or(SignatureError::NotEnoughSigsError)
    }
}

/// A weight of a nested weighted threshold: one key's weight, or a group
/// of keys counted as one weight.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(untagged)]
#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub enum NestedWeight {
    Key(ThresholdFraction),
    Group(WeightGroup),
}

/// Keys counted as one weight, written `{"<weight>": [<member weights>]}`:
/// the group adds `weight` once the weights of its signing members reach 1.
#[derive(Debug, Clone, PartialEq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
pub struct WeightGroup {
    pub weight: ThresholdFraction,
    pub members: Vec<ThresholdFraction>,
}

impl Serialize for WeightGroup {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(1))?;
        map.serialize_entry(&self.weight.to_string(), &self.members)?;
        map.end()
    }
}

impl<'de> Deserialize<'de> for WeightGroup {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let group = std::collections::BTreeMap::<String, Vec<ThresholdFraction>>::deserialize(
            deserializer,
        )?;
        match group.into_iter().collect::<Vec<_>>().as_slice() {
            [(weight, members)] => Ok(WeightGroup {
                weight: weight.parse().map_err(de::Error::custom)?,
                members: members.clone(),
            }),
            _ => Err(de::Error::custom("a weight group has exactly one weight")),
        }
    }
}

/// A clause of a nested weighted threshold, met when the weights of its
/// signing keys and met groups reach 1.
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
pub struct NestedClause(Vec<NestedWeight>);

impl NestedClause {
    /// Number of keys the clause speaks about.
    pub fn length(&self) -> usize {
        self.0
            .iter()
            .map(|weight| match weight {
                NestedWeight::Key(_) => 1,
                NestedWeight::Group(group) => group.members.len(),
            })
            .sum()
    }

    /// Whether the signatures of the keys at `sigs_indexes` meet the clause,
    /// its first key being the one at `start`.
    fn met(&self, start: usize, sigs_indexes: &[usize]) -> bool {
        let signed = |index: usize| sigs_indexes.contains(&index);
        let mut next = start;
        let mut total: Fraction = Zero::zero();
        for weight in &self.0 {
            match weight {
                NestedWeight::Key(fraction) => {
                    if signed(next) {
                        total = total + fraction.fraction;
                    }
                    next += 1;
                }
                NestedWeight::Group(group) => {
                    let members: Fraction = group
                        .members
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| signed(next + i))
                        .fold(Zero::zero(), |sum: Fraction, (_, member)| {
                            sum + member.fraction
                        });
                    if members >= One::one() {
                        total = total + group.weight.fraction;
                    }
                    next += group.members.len();
                }
            }
        }
        total >= One::one()
    }
}

/// Clauses of a nested weighted threshold, each met on its own keys, the
/// keys numbered across the clauses in order.
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
pub struct NestedClauses(Vec<NestedClause>);

impl NestedClauses {
    pub fn length(&self) -> usize {
        self.0.iter().map(NestedClause::length).sum()
    }

    fn met(&self, sigs_indexes: &[usize]) -> bool {
        let mut start = 0;
        self.0.iter().all(|clause| {
            let met = clause.met(start, sigs_indexes);
            start += clause.length();
            met
        })
    }
}

mod rkyv_serialization {
    use fraction::Fraction;

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[rkyv(remote = fraction::Sign)]
    #[rkyv(derive(Debug))]
    pub enum SignDef {
        Plus,
        Minus,
    }

    impl From<SignDef> for fraction::Sign {
        fn from(value: SignDef) -> Self {
            match value {
                SignDef::Plus => Self::Plus,
                SignDef::Minus => Self::Minus,
            }
        }
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[rkyv(remote = Fraction)]
    #[rkyv(derive(Debug))]
    pub enum FractionDef {
        Rational(
            #[rkyv(with = SignDef)] fraction::Sign,
            #[rkyv(with = RatioDef)] fraction::Ratio<u64>,
        ),
        Infinity(#[rkyv(with = SignDef)] fraction::Sign),
        NaN,
    }

    impl From<FractionDef> for Fraction {
        fn from(value: FractionDef) -> Self {
            match value {
                FractionDef::Rational(sign, ratio) => Fraction::Rational(sign, ratio),
                FractionDef::Infinity(sign) => Fraction::Infinity(sign),
                FractionDef::NaN => Fraction::NaN,
            }
        }
    }

    #[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
    #[rkyv(remote = fraction::Ratio<u64>)]
    #[rkyv(derive(Debug))]
    pub struct RatioDef {
        /// Numerator.
        #[rkyv(getter = fraction::Ratio::numer)]
        numer: u64,
        /// Denominator.
        #[rkyv(getter = fraction::Ratio::denom)]
        denom: u64,
    }

    impl From<RatioDef> for fraction::Ratio<u64> {
        fn from(value: RatioDef) -> Self {
            Self::new(value.numer, value.denom)
        }
    }
}

#[test]
fn test_enough_sigs() -> Result<(), SignatureError> {
    // Threshold: [[1/1], [1/2, 1/2, 1/2], [1/2,1/2]]
    let wt = MultiClauses::new_from_tuples(vec![vec![(1, 1)], vec![(1, 2), (1, 2), (1, 2)]]);
    let sigs_indexes: Vec<_> = vec![0, 1, 2, 3];

    // All signatures.
    assert!(wt.enough_signatures(&sigs_indexes.clone()).is_ok());

    // Enough signatures.
    let enough = vec![
        sigs_indexes[0].clone(),
        sigs_indexes[1].clone(),
        sigs_indexes[3].clone(),
    ];
    assert!(wt.enough_signatures(&enough.clone()).is_ok());

    let not_enough = vec![sigs_indexes[0].clone()];
    assert!(!wt.enough_signatures(&not_enough.clone()).is_ok());

    Ok(())
}

#[test]
pub fn test_weighted_treshold_serialization() -> Result<(), SignatureError> {
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

#[cfg(test)]
mod nested {
    use super::SignatureThreshold;

    /// The specification's example: two clauses, with groups of keys
    /// counted as one weight. Keys 0-2 form a group, 3 stands alone, 4-5
    /// form a group; in the second clause key 6 stands alone and 7-8 form a
    /// group.
    const EXAMPLE: &str =
        r#"[[{"1/2":["1/2","1/2","1/2"]},"1/2",{"1/2":["1","1"]}],["1/2",{"1/2":["1","1"]}]]"#;

    #[test]
    fn a_nested_threshold_reads_and_writes_back() {
        let threshold: SignatureThreshold = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(serde_json::to_string(&threshold).unwrap(), EXAMPLE);
        assert!(threshold.check_fits(9).is_ok());
        assert!(threshold.check_fits(8).is_err());

        let single = r#"["1/2",{"1/2":["1/2","1/2"]}]"#;
        let threshold: SignatureThreshold = serde_json::from_str(single).unwrap();
        assert_eq!(serde_json::to_string(&threshold).unwrap(), single);
        assert!(threshold.check_fits(3).is_ok());
    }

    #[test]
    fn a_group_counts_once_its_own_weights_reach_one() {
        let threshold: SignatureThreshold = serde_json::from_str(EXAMPLE).unwrap();
        // First clause: the 0-2 group (two of its halves) and key 3 make 1;
        // second clause: key 6 and the 7-8 group (one whole member) make 1.
        assert!(threshold.enough_signatures(&[0, 1, 3, 6, 7]).is_ok());
        // One member of the 0-2 group reaches only 1/2 inside the group, so
        // the group does not count and the first clause has only key 3.
        assert!(threshold.enough_signatures(&[0, 3, 6, 7]).is_err());
        // Both clauses must be met.
        assert!(threshold.enough_signatures(&[0, 1, 3]).is_err());
        // The 4-5 group with one whole member and key 3 also make 1.
        assert!(threshold.enough_signatures(&[3, 4, 6, 8]).is_ok());
    }

    #[test]
    fn a_group_written_with_several_weights_is_refused() {
        let two_keys = r#"[{"1/2":["1"],"1/3":["1"]}]"#;
        assert!(serde_json::from_str::<SignatureThreshold>(two_keys).is_err());
    }
}
