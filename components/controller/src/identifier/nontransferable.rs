use std::sync::Arc;


use crate::{
    communication::Communication, error::ControllerError, BasicPrefix, IdentifierPrefix,
    LocationScheme, SelfSigningPrefix,
};
use keri_core::{
    actor::{
        possible_response::PossibleResponse,
        prelude::{HashFunctionCode, SerializationFormats},
    },
    prefix::CesrPrimitive,
    database::{EscrowCreator, EventDatabase},
    event_message::signature::{Nontransferable, Signature},
    oobi_manager::storage::OobiStorageBackend,
    query::query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery},
};
use teliox::registry::RegistryStore;


pub struct NontransferableIdentifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + 'static,
    T: RegistryStore + 'static,
    S: OobiStorageBackend,
{
    id: BasicPrefix,
    communication: Arc<Communication<D, T, S>>,
}

impl<D, T, S> NontransferableIdentifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn new(public_key: BasicPrefix, communication: Arc<Communication<D, T, S>>) -> Self {
        Self {
            id: public_key,
            communication,
        }
    }

    /// Wrap `signature` in the [`SelfSigningPrefix`] variant matching the
    /// stored basic prefix's algorithm.
    ///
    /// `signature` must be the raw signature bytes produced by the
    /// corresponding private key (64 bytes for Ed25519 / secp256k1 / P-256,
    /// 114 for Ed448). Returns an error if the stored identifier uses a
    /// non-signing curve (X25519 / X448).
    pub fn sign(&self, signature: Vec<u8>) -> Result<Signature, ControllerError> {
        let code = self.id.signing_code().ok_or_else(|| {
            ControllerError::OtherError(format!(
                "NontransferableIdentifier({}) uses a non-signing curve",
                self.id.to_str()
            ))
        })?;
        let signature = SelfSigningPrefix::new(code, signature)
            .map_err(|e| ControllerError::OtherError(e.to_string()))?;
        Ok(Signature::NonTransferable(Nontransferable::Couplet(vec![
            (self.id.clone(), signature),
        ])))
    }

    pub fn query_log(
        &self,
        identifier: IdentifierPrefix,
        sn: u64,
        limit: u64,
        witness: BasicPrefix,
    ) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(sn),
                    i: identifier,
                    src: Some(IdentifierPrefix::Basic(witness)),
                    limit: Some(limit),
                },
            },
            &IdentifierPrefix::Basic(self.id.clone()),
            self.communication.events.version,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )
    }

    pub fn query_ksn(&self, id: &IdentifierPrefix, witness: BasicPrefix) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Ksn {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: None,
                    i: id.clone(),
                    src: Some(IdentifierPrefix::Basic(witness)),
                    limit: None,
                },
            },
            &IdentifierPrefix::Basic(self.id.clone()),
            self.communication.events.version,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )
    }

    pub async fn finalize_query(
        &self,
        witness: LocationScheme,
        qry: QueryEvent,
        signature: Signature,
    ) -> Result<PossibleResponse, ControllerError> {
        self.communication.resolve_loc_schema(&witness).await?;
        let signed_qry = SignedKelQuery {
            query: qry,
            signature: signature,
        };

        Ok(self
            .communication
            .send_query_to(&witness.eid, signed_qry)
            .await?)
    }
}
