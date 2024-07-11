use keri_core::actor::prelude::{HashFunctionCode, SelfAddressingIdentifier, SerializationFormats};
use keri_core::event::sections::seal::{EventSeal, Seal};
use keri_core::event_message::msg::KeriEvent;
use keri_core::event_message::timestamped::Timestamped;
use keri_core::prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix};
use teliox::event::verifiable_event::VerifiableEvent;
use teliox::query::{SignedTelQuery, TelQueryArgs, TelQueryEvent, TelQueryRoute};
use teliox::seal::{AttachedSourceSeal, EventSourceSeal};

use crate::error::ControllerError;

use super::mechanics::MechanicsError;
use super::Identifier;

impl Identifier {
    /// Generate `iss` event and `ixn` event with  seal to `iss`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn issue(
        &self,
        credential_digest: SelfAddressingIdentifier,
    ) -> Result<(IdentifierPrefix, Vec<u8>), ControllerError> {
        match self.registry_id.as_ref() {
            Some(registry_id) => {
                let tel = self.known_events.tel.clone();
                let iss = tel.make_issuance_event(registry_id, credential_digest)?;

                let vc_hash = iss.get_prefix();
                let seal = Seal::Event(EventSeal {
                    prefix: iss.get_prefix(),
                    sn: iss.get_sn(),
                    event_digest: iss.get_digest()?,
                });
                let ixn = self.anchor_with_seal(&[seal]).unwrap();

                let source_seal = EventSourceSeal {
                    sn: ixn.data.sn,
                    digest: ixn.digest()?,
                };
                let encoded_ixn = ixn.encode()?;

                let verifiable_event = VerifiableEvent {
                    event: iss,
                    seal: AttachedSourceSeal { seal: source_seal },
                };
                tel.processor.process(verifiable_event)?;

                Ok((vc_hash, encoded_ixn))
            }
            None => Err(ControllerError::OtherError("Tel not incepted".into())),
        }
    }

    /// Generate `rev` event and `ixn` event with  seal to `rev`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn revoke(
        &self,
        credential_sai: &SelfAddressingIdentifier,
    ) -> Result<Vec<u8>, ControllerError> {
        match &self.registry_id {
            Some(registry_id) => {
                let tel = self.known_events.tel.clone();
                let rev = tel.make_revoke_event(registry_id, credential_sai)?;

                let seal = Seal::Event(EventSeal {
                    prefix: rev.get_prefix(),
                    sn: rev.get_sn(),
                    event_digest: rev.get_digest()?,
                });
                let ixn = self.anchor_with_seal(&[seal]).unwrap();

                let source_seal = EventSourceSeal {
                    sn: ixn.data.sn,
                    digest: ixn.digest()?,
                };
                let encoded_ixn = ixn.encode()?;

                let verifiable_event = VerifiableEvent {
                    event: rev,
                    seal: AttachedSourceSeal { seal: source_seal },
                };
                tel.processor.process(verifiable_event)?;

                Ok(encoded_ixn)
            }
            None => Err(ControllerError::OtherError("Tel not incepted".into())),
        }
    }

    pub async fn finalize_issue(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        self.finalize_anchor(event, sig).await
    }

    pub async fn finalize_revoke(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        self.finalize_anchor(event, sig).await
    }

    pub fn query_tel(
        &self,
        registry_id: IdentifierPrefix,
        vc_identifier: IdentifierPrefix,
    ) -> Result<TelQueryEvent, ControllerError> {
        let route = TelQueryRoute::Tels {
            reply_route: "".into(),
            args: TelQueryArgs {
                i: Some(vc_identifier),
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
        issuer_id: &IdentifierPrefix,
        qry: TelQueryEvent,
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let query = match &self.id {
            IdentifierPrefix::Basic(bp) => {
                SignedTelQuery::new_nontrans(qry.clone(), bp.clone(), sig)
            }
            _ => {
                let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                SignedTelQuery::new_trans(qry.clone(), self.id.clone(), signatures)
            }
        };
        let witness = self.known_events.get_current_witness_list(issuer_id)?[0].clone();
        let watcher = self.watchers().unwrap()[0].clone();
        let location = self.known_events.get_loc_schemas(&watcher).unwrap()[0].clone();
        let tel_res = self
            .communication
            .tel_transport
            .send_query(query, location)
            .await
            .map_err(|e| MechanicsError::OtherError(e.to_string()))?;
        self.known_events
            .tel
            .parse_and_process_tel_stream(tel_res.as_bytes())
            .map_err(|e| MechanicsError::OtherError(e.to_string()))?;

        Ok(())
    }
}
