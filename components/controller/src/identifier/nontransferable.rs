use std::sync::Arc;

use crate::{
    communication::Communication, error::ControllerError, known_events::KnownEvents, BasicPrefix,
    IdentifierPrefix, LocationScheme, SeedPrefix, SelfSigningPrefix,
};
use keri_core::{
    actor::{
        prelude::{HashFunctionCode, SerializationFormats},
        simple_controller::PossibleResponse,
    },
    event::sections::seal::EventSeal,
    event_message::{
        msg::KeriEvent,
        signature::{self, Nontransferable, Signature},
        timestamped::Timestamped,
    },
    oobi::Scheme,
    processor::escrow::EscrowConfig,
    query::query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery},
    signer::Signer,
    transport::default::DefaultTransport,
};
use teliox::query::{SignedTelQuery, TelQueryArgs, TelQueryEvent, TelQueryRoute};

use super::mechanics::MechanicsError;

pub struct NontransferableIdentifier {
    id: BasicPrefix,
    communication: Arc<Communication>,
}

impl NontransferableIdentifier {
    pub fn new(public_key: BasicPrefix, communication: Arc<Communication>) -> Self {
        Self {
            id: public_key,
            communication,
        }
    }

    pub fn sign(&self, signature: Vec<u8>) -> Signature {
        Signature::NonTransferable(Nontransferable::Couplet(vec![(
            self.id.clone(),
            SelfSigningPrefix::Ed25519Sha512(signature),
        )]))
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
            .send_query_to(&witness.eid, Scheme::Http, signed_qry)
            .await?)
    }

    pub fn query_tel(
        &self,
        registry_id: IdentifierPrefix,
        vc_identifier: Option<IdentifierPrefix>,
    ) -> Result<TelQueryEvent, ControllerError> {
        let route = TelQueryRoute::Tels {
            reply_route: "".into(),
            args: TelQueryArgs {
                i: vc_identifier,
                ri: Some(registry_id),
            },
        };
        let env = Timestamped::new(route);
        Ok(KeriEvent::new(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            env,
        ))
    }

    pub async fn finalize_query_tel(
        &self,
        witness_location: LocationScheme,
        qry: TelQueryEvent,
        sig: Signature,
    ) -> Result<String, MechanicsError> {
        let signed_qry = SignedTelQuery {
            query: qry,
            signature: sig,
        };

        let tel_res = self
            .communication
            .tel_transport
            .send_query(signed_qry, witness_location)
            .await
            .map_err(|e| MechanicsError::OtherError(e.to_string()))?;
        Ok(tel_res)
    }
}
