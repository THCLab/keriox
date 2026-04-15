//! TEL credential status queries.
//!
//! These functions provide a simple interface for checking whether a
//! credential is currently `Issued`, `Revoked`, or `Unknown` without
//! requiring callers to interact with `TelState` or `ManagerTelState` directly.
//!
//! For issuing and revoking credentials see [`crate::operations`]. For
//! creating a registry see [`crate::operations::incept_registry`].

use keri_controller::IdentifierPrefix;
use keri_core::actor::prelude::SelfAddressingIdentifier;
use teliox::state::vc_state::TelState;

use crate::{
    error::{Error, Result},
    identifier::Identifier,
    operations::ed25519_sig,
    types::CredentialStatus,
};

/// Query the TEL for a credential's current status (network call).
///
/// Sends a signed TEL query to the first configured watcher and processes
/// the response. After this call, [`get_credential_status`] will return the
/// up-to-date status without another network round-trip.
///
/// # Errors
/// - [`Error::NoWatchers`] if no watcher is configured for the identifier.
/// - [`Error::RegistryNotIncepted`] if `registry_id` is not known locally.
/// - [`Error::Mechanics`] on network or processing failures.
/// - [`Error::Signing`] if signing the query fails.
pub async fn check_credential_status<S: crate::operations::SigningBackend>(
    id: &Identifier,
    signer: &S,
    registry_id: &IdentifierPrefix,
    credential_said: &SelfAddressingIdentifier,
) -> Result<CredentialStatus> {
    id.find_management_tel_state(registry_id)?
        .ok_or_else(|| Error::RegistryNotIncepted(registry_id.clone()))?;

    let vc_id = IdentifierPrefix::self_addressing(credential_said.clone());

    let qry = id.query_tel(registry_id.clone(), vc_id)?;
    let encoded = qry
        .encode()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    let sig = ed25519_sig(signer, &encoded)?;
    id.finalize_query_tel(qry, sig).await?;

    get_credential_status(id, credential_said)
}

/// Return the last known local TEL state without a network call.
///
/// Returns [`CredentialStatus::Unknown`] if the TEL has not been queried yet
/// or the credential is not known locally.
///
/// # Errors
/// - [`Error::Controller`] on database access failures.
pub fn get_credential_status(
    id: &Identifier,
    credential_said: &SelfAddressingIdentifier,
) -> Result<CredentialStatus> {
    match id.find_vc_state(credential_said)? {
        Some(TelState::Issued(_)) => Ok(CredentialStatus::Issued),
        Some(TelState::Revoked) => Ok(CredentialStatus::Revoked),
        Some(TelState::NotIssued) | None => Ok(CredentialStatus::Unknown),
    }
}
