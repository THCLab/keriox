//! Signed message containers returned by the high-level signing API.

use std::fmt;

use crate::error::{Error, Result};
use crate::ids::IdentityId;

/// A payload signed by an identity, encoded as a self-describing CESR string.
///
/// The CESR text contains the payload and the signature(s); it is safe to
/// store or transmit as a plain string and feed back into
/// [`crate::Keri::verify`] on any machine.
#[derive(Debug, Clone)]
pub struct SignedMessage {
    pub(crate) cesr: String,
    pub(crate) signer: IdentityId,
}

impl SignedMessage {
    /// The full signed message as CESR text — what you store or send.
    pub fn as_cesr(&self) -> &str {
        &self.cesr
    }

    /// Consume and return the CESR text.
    pub fn into_cesr(self) -> String {
        self.cesr
    }

    /// Who signed this message.
    pub fn signer(&self) -> &IdentityId {
        &self.signer
    }

    /// Re-construct a `SignedMessage` from CESR text received from elsewhere.
    ///
    /// This only parses the stream and reads the signer's identity — it does
    /// **not** check the signature. Call [`crate::Keri::verify`] for that.
    pub fn from_cesr(cesr: &str) -> Result<Self> {
        let signer = signer_of(cesr.as_bytes())?;
        Ok(SignedMessage {
            cesr: cesr.to_string(),
            signer,
        })
    }
}

impl fmt::Display for SignedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.cesr)
    }
}

/// A successfully verified message: the original payload plus the proven
/// identity of whoever signed it.
#[derive(Debug, Clone)]
pub struct Verified {
    /// The original bytes that were signed.
    pub payload: Vec<u8>,
    /// The identity whose signature was verified.
    pub signer: IdentityId,
}

impl Verified {
    /// The payload as UTF-8 text, if it is text.
    pub fn payload_str(&self) -> Result<&str> {
        std::str::from_utf8(&self.payload).map_err(|e| Error::InvalidInput {
            expected: "UTF-8 text payload",
            cause: e.to_string(),
        })
    }
}

/// Extract the signer's identity from a signed CESR stream without verifying.
pub(crate) fn signer_of(cesr: &[u8]) -> Result<IdentityId> {
    let (_, signatures) = crate::advanced::signing::parse_signed_envelope(cesr)?;
    signatures
        .iter()
        .find_map(|s| s.get_signer())
        .map(IdentityId::from)
        .ok_or(Error::InvalidInput {
            expected: "signed CESR message with an identifiable signer",
            cause: "no signer information found in signature attachments".to_string(),
        })
}
