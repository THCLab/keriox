//! IPEX, the Issuance and Presentation Exchange: granting a presented
//! credential to another identifier and admitting a grant, signed by an
//! identifier's current keys. A grant travels as one stream (the
//! credential's registry events, then the grant), so any channel that
//! carries bytes, such as a messagebox, delivers it.

use keri_controller::IdentifierPrefix;
use teliox::{
    ipex::{Admit, Grant},
    registry::Presentation,
};

use crate::advanced::{
    error::{Error, Result},
    identifier::Identifier,
    operations::{wrap_sig, SigningBackend},
};

/// Grants `presentation` to `recipient` with `message`; returns the stream
/// to deliver.
///
/// # Errors
/// - [`Error::Controller`] if this identifier's key state is not known.
/// - [`Error::Signing`] if signing fails.
pub fn grant<S: SigningBackend>(
    id: &Identifier,
    signer: &S,
    recipient: &IdentifierPrefix,
    presentation: &Presentation,
    message: &str,
) -> Result<Vec<u8>> {
    let grant = id.grant(recipient, message, presentation);
    let bytes = grant
        .signing_bytes()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = wrap_sig(signer, &bytes)?;
    id.finalize_grant(grant, presentation, sig)
}

/// Admits `grant`, sent to this identifier, with `message`; returns the
/// admit to deliver to the grant's sender.
///
/// # Errors
/// - [`Error::Signing`] if signing fails.
pub fn admit<S: SigningBackend>(
    id: &Identifier,
    signer: &S,
    grant: &Grant,
    message: &str,
) -> Result<Vec<u8>> {
    let admit: Admit = id.admit(grant, message)?;
    let bytes = admit
        .signing_bytes()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = wrap_sig(signer, &bytes)?;
    id.finalize_admit(admit, sig)
}
