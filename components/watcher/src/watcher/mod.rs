pub mod config;
mod tel_providing;
mod watcher_data;

use std::{
    fs::create_dir_all,
    sync::{Arc, Mutex},
};

use keri_core::{
    actor::{
        error::ActorError, parse_event_stream, parse_notice_stream, parse_query_stream,
        parse_reply_stream, possible_response::PossibleResponse,
    }, database::redb::RedbDatabase, error::Error, event_message::signed_event_message::Message, oobi::{error::OobiError, EndRole, LocationScheme}, prefix::{BasicPrefix, IdentifierPrefix}, query::reply_event::{ReplyRoute, SignedReply}
};
use tel_providing::RegistryMapping;
use teliox::{database::sled_db::SledEventDatabase, event::parse_tel_query_stream};
use teliox::{
    event::verifiable_event::VerifiableEvent,
    processor::{validator::TelEventValidator, TelReplyType},
    query::TelQueryRoute,
};
use tokio::sync::mpsc::{channel, Receiver};
use watcher_data::WatcherData;

use crate::WatcherConfig;

enum WitnessResp {
    Kel(Vec<Message>),
    Tel(Vec<VerifiableEvent>),
}

pub struct Watcher {
    pub(crate) watcher_data: Arc<WatcherData>,
    recv: Mutex<Receiver<IdentifierPrefix>>,
    tel_recv: Mutex<Receiver<(IdentifierPrefix, IdentifierPrefix)>>,
    // Maps registry id to witness id provided by oobi
    registry_id_mapping: RegistryMapping,
}

impl Watcher {
    pub fn new(config: WatcherConfig) -> Result<Self, ActorError> {
        let (tx, rx) = channel::<IdentifierPrefix>(100);
        let (tel_tx, tel_rx) = channel::<(IdentifierPrefix, IdentifierPrefix)>(100);
        let tel_storage_path = config.tel_storage_path.clone();
        create_dir_all(&tel_storage_path).unwrap();
        let mut registry_ids_storage_path = tel_storage_path.clone();
        registry_ids_storage_path.push("registry");
        Ok(Watcher {
            watcher_data: WatcherData::new(config, tx, tel_tx)?,
            recv: Mutex::new(rx),
            tel_recv: Mutex::new(tel_rx),
            registry_id_mapping: RegistryMapping::new(&registry_ids_storage_path)
                .map_err(|e| ActorError::GeneralError(e.to_string()))?,
        })
    }

    pub fn prefix(&self) -> BasicPrefix {
        self.watcher_data.prefix.clone()
    }

    pub fn signed_location(&self, eid: &IdentifierPrefix) -> Result<Vec<SignedReply>, ActorError> {
        self.watcher_data.get_loc_scheme_for_id(eid)
    }

    pub async fn process_update_requests(&self) {
        let mut recv = self.recv.lock().unwrap();

        while let Some(received) = recv.recv().await {
            let _ = self.watcher_data.update_local_kel(&received).await;
        }
    }

    pub async fn process_update_tel_requests(&self) -> Result<(), ActorError> {
        let mut recv = self.tel_recv.lock().unwrap();
        while let Some((ri, vc_id)) = recv.recv().await {
            let who_to_ask = self
                .registry_id_mapping
                .get(&ri)
                .map_err(|e| ActorError::GeneralError(e.to_string()))
                .unwrap()
                .ok_or(ActorError::GeneralError(format!(
                    "Can't find TEL of id: {}",
                    ri
                )))?;

            self.watcher_data
                .tel_update(&ri, &vc_id, who_to_ask.clone())
                .await?;
        }
        Ok(())
    }

    pub fn oobi(&self) -> LocationScheme {
        LocationScheme::new(
            IdentifierPrefix::Basic(self.prefix()),
            self.watcher_data.address.scheme().parse().unwrap(),
            self.watcher_data.address.clone(),
        )
    }
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<(), ActorError> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .watcher_data
            .get_loc_scheme_for_id(&er.eid.clone())?
            .get(0)
            .ok_or(ActorError::NoLocation { id: er.eid.clone() })?
            .reply
            .data
            .data
            .clone();

        if let ReplyRoute::LocScheme(loc) = loc_scheme {
            let oobis = self
                .watcher_data
                .transport
                .request_end_role(loc, er.cid.clone(), er.role, er.eid.clone())
                .await?;
            match Self::parse_witness_response(&oobis)? {
                WitnessResp::Kel(kel_event) => {
                    for m in kel_event {
                        match m {
                            Message::Op(op) => {
                                self.watcher_data.process_op(op).await?;
                            }
                            Message::Notice(not) => {
                                self.watcher_data.process_notice(not)?;
                            }
                        }
                    }
                }
                WitnessResp::Tel(tel_events) => {
                    // check tel event
                    for ev in tel_events {
                        let digest = ev.event.get_digest().unwrap();
                        let issuer_id = match ev.event {
                            teliox::event::Event::Management(man) => match man.data.event_type {
                                teliox::event::manager_event::ManagerEventType::Vcp(vcp) => {
                                    vcp.issuer_id.clone()
                                }
                                teliox::event::manager_event::ManagerEventType::Vrt(_) => todo!(),
                            },
                            teliox::event::Event::Vc(_) => todo!(),
                        };
                        let seal = &ev.seal;
                        TelEventValidator::<SledEventDatabase, RedbDatabase>::check_kel_event(
                            self.watcher_data.event_storage.clone(),
                            seal,
                            &issuer_id,
                            digest,
                        )
                        .unwrap();
                        self.registry_id_mapping
                            .save(er.cid.clone(), er.eid.clone())
                            .map_err(|e| ActorError::GeneralError(e.to_string()))?;
                    }
                }
            }
            //
            Ok(())
        } else {
            Err(OobiError::InvalidMessageType)?
        }
    }

    pub async fn resolve_loc_scheme(&self, loc: &LocationScheme) -> Result<(), ActorError> {
        let oobis = self
            .watcher_data
            .transport
            .request_loc_scheme(loc.clone())
            .await?;
        self.watcher_data.process_ops(oobis).await?;
        Ok(())
    }

    fn parse_witness_response(input: &[u8]) -> Result<WitnessResp, ActorError> {
        match parse_event_stream(input) {
            Ok(msgs) => Ok(WitnessResp::Kel(msgs)),
            Err(_) => {
                // try to parse tel event
                VerifiableEvent::parse(input)
                    .map(|tel_events| WitnessResp::Tel(tel_events))
                    .map_err(|e| ActorError::GeneralError(e.to_string()))
            }
        }
    }

    pub fn parse_and_process_notices(&self, input_stream: &[u8]) -> Result<(), Error> {
        parse_notice_stream(input_stream)?
            .into_iter()
            .try_for_each(|notice| self.watcher_data.process_notice(notice))
    }

    pub async fn parse_and_process_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<PossibleResponse>, ActorError> {
        let mut responses = Vec::new();
        for query in parse_query_stream(input_stream)? {
            match query {
                keri_core::query::query_event::SignedQueryMessage::KelQuery(kqry) => {
                    let result = self.watcher_data.process_query(kqry).await?;
                    if let Some(response) = result {
                        responses.push(response);
                    }
                }
                keri_core::query::query_event::SignedQueryMessage::MailboxQuery(_mqry) => {
                    unimplemented!()
                }
            }
        }
        Ok(responses)
    }

    pub fn parse_and_process_replies(&self, input_stream: &[u8]) -> Result<(), ActorError> {
        for reply in parse_reply_stream(input_stream)? {
            self.watcher_data.process_reply(reply)?;
        }
        Ok(())
    }

    pub async fn parse_and_process_tel_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<TelReplyType>, ActorError> {
        let tel_queries = parse_tel_query_stream(input_stream)
            .map_err(|_e| ActorError::GeneralError("Can't parse TEL query stream".to_string()))?
            .into_iter();

        let mut out = vec![];
        for qry in tel_queries {
            // TODO Verify signature
            let (ri, vc_id) = match qry.query.data.data {
                TelQueryRoute::Tels {
                    reply_route: _,
                    args,
                } => match (args.ri, args.i) {
                    (Some(ri), Some(i)) => (ri, i),
                    _ => {
                        return Err(ActorError::GeneralError(
                            "Wrong TEL query format. `ri` and `i` field required".to_string(),
                        ))
                    }
                },
            };
            // Query witness about new tel events
            self.watcher_data
                .tel_tx
                .send((ri.clone(), vc_id.clone()))
                .await
                .map_err(|_e| {
                    ActorError::GeneralError("Internal watcher error: channel problem".to_string())
                })?;

            // Check if you have tel to forward
            if let Some(tel) = self
                .watcher_data
                .tel_to_forward
                .get(&ri, &vc_id)
                .map_err(|e| ActorError::GeneralError(e.to_string()))?
            {
                out.push(TelReplyType::Tel(tel.clone().as_bytes().to_vec()))
            };
        }
        Ok(out)
    }
}
