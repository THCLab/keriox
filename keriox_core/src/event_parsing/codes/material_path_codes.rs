use std::str::FromStr;

use crate::event_parsing::{
    error::Error,
    parsing::{adjust_with_num, b64_to_num},
};

use super::DerivationCode;

#[derive(Debug, PartialEq, Eq)]
pub enum MaterialPathCode {
    ZeroLeadBytes(u16),
    OneLeadBytes(u16),
    TwoLeadBytes(u16),
}

impl DerivationCode for MaterialPathCode {
    fn soft_size(&self) -> usize {
        2
    }

    fn hard_size(&self) -> usize {
        2
    }

    fn value_size(&self) -> usize {
        0
    }

    fn to_str(&self) -> String {
        let (code, data_len) = match self {
            MaterialPathCode::ZeroLeadBytes(data_lenght) => ("4A", data_lenght),
            MaterialPathCode::OneLeadBytes(data_length) => ("5A", data_length),
            MaterialPathCode::TwoLeadBytes(data_length) => ("6A", data_length),
        };
        let data = adjust_with_num(data_len.to_owned(), self.soft_size());
        [code, &data].join("")
    }
}

impl MaterialPathCode {
    pub fn size(&self) -> u16 {
        match self {
            MaterialPathCode::ZeroLeadBytes(n) => n,
            MaterialPathCode::OneLeadBytes(n) => n,
            MaterialPathCode::TwoLeadBytes(n) => n,
        }
        .to_owned()
    }

    pub fn lead_bytes_len(&self) -> usize {
        match self {
            MaterialPathCode::ZeroLeadBytes(_) => 0,
            MaterialPathCode::OneLeadBytes(_) => 1,
            MaterialPathCode::TwoLeadBytes(_) => 2,
        }
    }

    pub fn new(lead_length: usize, data_len: u16) -> Result<Self, Error> {
        match lead_length {
            0 => Ok(Self::ZeroLeadBytes(data_len)),
            1 => Ok(Self::OneLeadBytes(data_len)),
            2 => Ok(Self::TwoLeadBytes(data_len)),
            _ => Err(Error::IncorrectLengthError(
                "Wrong lead bytes length".into(),
            )),
        }
    }
}

impl FromStr for MaterialPathCode {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let code = s.get(..2).ok_or_else(|| Error::EmptyCodeError)?;
        let count_part = s.get(2..4).ok_or_else(|| Error::EmptyCodeError)?;
        let count = b64_to_num(count_part.as_bytes())?;
        match code {
            "4A" => Ok(Self::ZeroLeadBytes(count)),
            "5A" => Ok(Self::OneLeadBytes(count)),
            "6A" => Ok(Self::TwoLeadBytes(count)),
            _ => Err(Error::UnknownCodeError),
        }
    }
}

#[test]
pub fn test_material_path_code_to_str() -> Result<(), Error> {
    assert_eq!(MaterialPathCode::new(0, 1)?.to_str(), "4AAB".to_string());
    assert_eq!(MaterialPathCode::new(1, 100)?.to_str(), "5ABk".to_string());
    assert_eq!(MaterialPathCode::new(2, 64)?.to_str(), "6ABA".to_string());
    assert!(MaterialPathCode::new(3, 64).is_err());

    Ok(())
}

#[test]
pub fn test_material_path_code_from_str() -> Result<(), Error> {
    assert_eq!(MaterialPathCode::new(0, 1)?, "4AAB".parse()?);
    assert_eq!(MaterialPathCode::new(1, 100)?, "5ABk".parse()?);
    assert_eq!(MaterialPathCode::new(2, 64)?, "6ABA".parse()?);
    assert_eq!(
        Err(Error::UnknownCodeError),
        "AAAA".parse::<MaterialPathCode>()
    );

    Ok(())
}
