use std::str::FromStr;

use chrono::SecondsFormat;

use crate::event_parsing::{error::Error, primitives::Timestamp};

use super::DerivationCode;

#[derive(Debug, PartialEq)]
pub struct TimestampCode;

impl DerivationCode for TimestampCode {
    fn hard_size(&self) -> usize {
        4
    }

    fn soft_size(&self) -> usize {
        0
    }

    fn value_size(&self) -> usize {
        32
    }

    fn to_str(&self) -> String {
        "1AAG".into()
    }
}

impl FromStr for TimestampCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..4).ok_or_else(|| Error::EmptyCodeError)?;

        match code {
            "1AAG" => Ok(TimestampCode),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

pub fn pack_datetime(dt: &Timestamp) -> String {
    [
        TimestampCode.to_str(),
        dt.to_rfc3339_opts(SecondsFormat::Micros, false)
            .replace(':', "c")
            .replace('.', "d")
            .replace('+', "p"),
    ]
    .concat()
}

#[test]
pub fn test_pack_datetime() {
    let dt = "2022-10-25T12:04:30.175309+00:00"
        .parse::<Timestamp>()
        .unwrap();
    let expected_str = "1AAG2022-10-25T12c04c30d175309p00c00";
    assert_eq!(expected_str, pack_datetime(&dt));
}
