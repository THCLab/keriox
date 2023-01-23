use crate::error::Error;

use super::{SelfAddressingPrefix, derivation::SelfAddressing};

/// Self Addressing Data
pub trait SAD {
	fn dummy_sad(&self, sa: &SelfAddressing) -> Vec<u8>;
	fn compute_digest(&self, sa: SelfAddressing) -> SelfAddressingPrefix {
		sa.derive(&self.dummy_sad(&sa))
	}
	fn check_digest(&self) -> Result<(), Error> {todo!()}
}