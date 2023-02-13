use crate::error::Error;

use super::{derivation::SelfAddressing, SelfAddressingPrefix};

/// Self Addressing Data
pub trait SAD {
    fn get_digest(&self) -> SelfAddressingPrefix;
    fn dummy_event(&self) -> Result<Vec<u8>, Error>;
    fn check_digest(&self) -> Result<(), Error> {
        let dummy: Vec<u8> = self.dummy_event()?;
        self.get_digest()
            .verify_binding(&dummy)
            .then(|| ())
            .ok_or(Error::IncorrectDigest)
    }
}
