//! Ephemeral non-transferable identifier for pulling data from witnesses.
//!
//! An [`EphemeralIdentifier`] is a throwaway, non-transferable identifier
//! backed by a temporary database. It can sign witness queries without any
//! pre-existing local state — useful for fetching another identifier's KEL,
//! key state (KSN), or TEL from a witness before a full identifier exists
//! locally (e.g. during import).
//!
//! The temporary database is removed when the value is dropped.

use std::sync::Arc;

use keri_controller::{
    communication::{Communication, HTTPTelTransport, SendingError},
    error::ControllerError,
    identifier::nontransferable::NontransferableIdentifier,
    known_events::RedbKnownEvents,
    BasicPrefix, IdentifierPrefix, LocationScheme,
};
use keri_core::{
    actor::{
        error::ActorError, possible_response::PossibleResponse, prelude::Message, QueryError,
        SignedQueryError,
    },
    processor::escrow::EscrowConfig,
    signer::Signer,
    transport::default::DefaultTransport,
};
use tempfile::TempDir;

use crate::advanced::error::{Error, Result};

type RedbNontransferableIdentifier = NontransferableIdentifier<
    keri_core::database::redb::RedbDatabase,
    teliox::database::redb::RedbTelDatabase,
    keri_core::oobi_manager::storage::RedbOobiStorage,
>;

/// A throwaway non-transferable identifier for signed witness queries.
pub struct EphemeralIdentifier {
    signer: Arc<Signer>,
    id: RedbNontransferableIdentifier,
    /// Keeps the temporary database directory alive for the value's lifetime.
    _tmp_dir: TempDir,
}

impl EphemeralIdentifier {
    /// Create a fresh ephemeral identifier with a random Ed25519 key and a
    /// temporary database.
    ///
    /// # Errors
    /// - [`Error::PersistenceError`] if the temporary directory cannot be created.
    /// - [`Error::Controller`] if the temporary database cannot be initialised.
    pub fn new() -> Result<Self> {
        let signer = Arc::new(Signer::new());
        let public_key = BasicPrefix::Ed25519NT(signer.public_key());
        let tmp_dir = tempfile::Builder::new()
            .prefix("keri-sdk-ephemeral")
            .tempdir()
            .map_err(|e| Error::PersistenceError(format!("temporary dir creation: {e}")))?;

        let events = Arc::new(RedbKnownEvents::with_redb(
            tmp_dir.path().to_path_buf(),
            EscrowConfig::default(),
        )?);
        let communication = Arc::new(Communication {
            events,
            transport: Box::new(DefaultTransport::new()),
            tel_transport: Box::new(HTTPTelTransport),
        });
        let id = NontransferableIdentifier::new(public_key, communication);
        Ok(Self {
            signer,
            id,
            _tmp_dir: tmp_dir,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<keri_core::event_message::signature::Signature> {
        let raw = self
            .signer
            .sign(data)
            .map_err(|e| Error::Signing(e.to_string()))?;
        Ok(self.id.sign(raw)?)
    }

    /// Pull an identifier's KEL from a witness.
    ///
    /// Queries log entries starting at sequence number `sn`, up to `limit`
    /// entries. Returns one CESR-encoded message per KEL entry, or `None`
    /// when the witness does not know the identifier.
    ///
    /// # Errors
    /// - [`Error::Controller`] on network or query failures.
    pub async fn pull_kel(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        limit: u64,
        witness: &LocationScheme,
    ) -> Result<Option<Vec<String>>> {
        let witness_id = basic_eid(witness)?;
        let qry = self.id.query_log(id.clone(), sn, limit, witness_id);
        let signature = self.sign(
            &qry.encode()
                .map_err(|e| Error::EncodingError(e.to_string()))?,
        )?;
        match self.id.finalize_query(witness.clone(), qry, signature).await {
            Ok(PossibleResponse::Kel(messages)) => {
                let cesr = messages
                    .into_iter()
                    .map(message_to_cesr)
                    .collect::<Result<Vec<_>>>()?;
                Ok(Some(cesr))
            }
            Ok(other) => Err(Error::Other(format!(
                "unexpected response from witness: {other:?}"
            ))),
            Err(ControllerError::SendingError(SendingError::ActorInternalError(
                ActorError::QueryError(SignedQueryError::QueryError(QueryError::UnknownId {
                    ..
                })),
            ))) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Pull an identifier's key state notice (KSN) from a witness and return
    /// it as pretty-printed JSON.
    ///
    /// # Errors
    /// - [`Error::Controller`] on network or query failures.
    pub async fn pull_ksn(&self, id: &IdentifierPrefix, witness: &LocationScheme) -> Result<String> {
        let witness_id = basic_eid(witness)?;
        let qry = self.id.query_ksn(id, witness_id);
        let signature = self.sign(
            &qry.encode()
                .map_err(|e| Error::EncodingError(e.to_string()))?,
        )?;
        match self.id.finalize_query(witness.clone(), qry, signature).await? {
            PossibleResponse::Ksn(ksn) => serde_json::to_string_pretty(&ksn.reply.data)
                .map_err(|e| Error::EncodingError(e.to_string())),
            other => Err(Error::Other(format!(
                "unexpected response from witness: {other:?}"
            ))),
        }
    }

    /// Pull a registry's TEL (optionally narrowed to one credential) from a
    /// witness and return the raw CESR response.
    ///
    /// # Errors
    /// - [`Error::Controller`] / [`Error::Mechanics`] on network failures.
    pub async fn pull_tel(
        &self,
        registry_id: &IdentifierPrefix,
        vc_id: Option<IdentifierPrefix>,
        witness: &LocationScheme,
    ) -> Result<String> {
        let qry = self.id.query_tel(registry_id.clone(), vc_id)?;
        let signature = self.sign(
            &qry.encode()
                .map_err(|e| Error::EncodingError(e.to_string()))?,
        )?;
        Ok(self
            .id
            .finalize_query_tel(witness.clone(), qry, signature)
            .await?)
    }
}

fn basic_eid(witness: &LocationScheme) -> Result<BasicPrefix> {
    match &witness.eid {
        IdentifierPrefix::Basic(basic_prefix) => Ok(basic_prefix.clone()),
        other => Err(Error::Other(format!(
            "witness identifier must be a basic prefix, got: {other}"
        ))),
    }
}

fn message_to_cesr(message: Message) -> Result<String> {
    let bytes = message
        .to_cesr()
        .map_err(|e| Error::EncodingError(e.to_string()))?;
    String::from_utf8(bytes).map_err(|e| Error::EncodingError(e.to_string()))
}
