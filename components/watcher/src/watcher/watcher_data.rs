use std::{fs::File, sync::Arc};

use futures::future::join_all;
use itertools::Itertools;
use keri_core::actor::possible_response::PossibleResponse;
use keri_core::error::Error;
use keri_core::oobi::error::OobiError;
use keri_core::oobi::LocationScheme;
use keri_core::prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix};
use keri_core::processor::escrow::default_escrow_bus;
use keri_core::processor::escrow::reply_escrow::ReplyEscrow;
use keri_core::query::{
    reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    ReplyType,
};
use keri_core::state::IdentifierState;
use keri_core::{
    actor::{
        error::ActorError,
        prelude::{HashFunctionCode, SerializationFormats},
        process_notice, process_reply, QueryError, SignedQueryError,
    },
    oobi::{Role, Scheme},
};
use keri_core::{
    database::redb::RedbDatabase,
    event_message::{
        msg::KeriEvent,
        signed_event_message::{Message, Notice, Op},
        timestamped::Timestamped,
    },
};
use keri_core::{
    oobi_manager::{OobiManager, storage::OobiStorageBackend},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
    transport::Transport,
};
use keri_core::{
    processor::notification::JustNotification,
    query::query_event::{
        LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery, SignedQueryMessage,
    },
};
use teliox::query::{SignedTelQuery, TelQueryArgs, TelQueryRoute};
use tokio::sync::mpsc::Sender;

use crate::transport::WatcherTelTransport;

use super::{config::WatcherConfig, health::WitnessHealthTracker, tel_providing::TelToForward};

/// A KEL update request with an optional completion signal.
pub(crate) struct UpdateRequest {
    pub id: IdentifierPrefix,
    /// If set, the sender will be notified when the update completes.
    pub completion: Option<tokio::sync::oneshot::Sender<Result<(), ActorError>>>,
}

pub struct WatcherData<S: OobiStorageBackend> {
    pub address: url::Url,
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor<RedbDatabase>,
    pub event_storage: Arc<EventStorage<RedbDatabase>>,
    pub oobi_manager: OobiManager<S>,
    pub signer: Arc<Signer>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn WatcherTelTransport + Send + Sync>,
    /// Watcher will update KEL of the identifiers that have been sent to this channel.
    tx: Sender<UpdateRequest>,
    /// Watcher will update TEL of the identifiers (registry_id, vc_id) that have been sent to this channel.
    pub tel_tx: Sender<(IdentifierPrefix, IdentifierPrefix)>,
    pub(super) tel_to_forward: Arc<TelToForward>,
    reply_escrow: Arc<ReplyEscrow<RedbDatabase>>,
    pub(crate) health_tracker: Arc<WitnessHealthTracker>,
}

impl<S: OobiStorageBackend> WatcherData<S> {
    pub(crate) fn new(
        config: WatcherConfig,
        tx: Sender<UpdateRequest>,
        tel_tx: Sender<(IdentifierPrefix, IdentifierPrefix)>,
        oobi_manager: OobiManager<S>,
    ) -> Result<Arc<Self>, ActorError> {
        let WatcherConfig {
            public_address,
            db_path,
            priv_key,
            transport,
            escrow_config,
            tel_storage_path,
            tel_transport,
            poll_interval: _, // handled by Watcher, not WatcherData
        } = config;
        let mut tel_to_forward_path = tel_storage_path.clone();
        tel_to_forward_path.push("to_forward");

        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );

        let events_db = {
            let mut path = db_path.clone();
            path.push("events_database");
            let _file = File::create(&path).unwrap();
            Arc::new(RedbDatabase::new(&path).unwrap())
        };

        let (notification_bus, _escrows) = default_escrow_bus(events_db.clone(), escrow_config, None);
        let reply_escrow = Arc::new(ReplyEscrow::new(events_db.clone()));
        notification_bus.register_observer(
            reply_escrow.clone(),
            vec![
                JustNotification::KeyEventAdded,
                JustNotification::KsnOutOfOrder,
            ],
        );

        let prefix = BasicPrefix::Ed25519NT(signer.public_key()); // watcher uses non transferable key
        let processor = BasicProcessor::new(events_db.clone(), Some(notification_bus));

        let storage = Arc::new(EventStorage::new_redb(events_db));

        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(prefix.clone()),
            public_address.scheme().parse().map_err(|_e| {
                ActorError::GeneralError(format!("Unsupported scheme {}", public_address.scheme()))
            })?,
            public_address.clone(),
        );
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            prefix.clone(),
            SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.encode()?)?),
        );
        oobi_manager.save_oobi(&signed_reply)?;

        let watcher = Arc::new(Self {
            address: public_address,
            prefix,
            processor,
            event_storage: storage,
            signer,
            oobi_manager,
            transport,
            tx,
            tel_to_forward: Arc::new(
                TelToForward::new(tel_to_forward_path)
                    .map_err(|e| ActorError::GeneralError(e.to_string()))?,
            ),
            tel_tx,
            tel_transport,
            reply_escrow,
            health_tracker: Arc::new(WitnessHealthTracker::new()),
        });
        Ok(watcher.clone())
    }

    /// Get location scheme from OOBI manager and sign it.
    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Vec<SignedReply>, ActorError> {
        let loc_scheme = self.oobi_manager.get_loc_scheme(eid)?;
        if loc_scheme.is_empty() {
            return Err(ActorError::NoLocation { id: eid.clone() });
        } else {
            loc_scheme
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.encode()?)?;
                    Ok(SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.prefix.clone(),
                        SelfSigningPrefix::Ed25519Sha512(signature),
                    ))
                })
                .collect::<Result<_, ActorError>>()
        }
    }

    pub fn get_end_role_for_id(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Vec<SignedReply>, ActorError> {
        self.oobi_manager
            .get_end_role(&cid, role)
            .map(|el| el.unwrap_or_default())
            .map_err(ActorError::from)
    }

    pub fn get_signed_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let ksn = self
            .event_storage
            .get_ksn_for_prefix(prefix, SerializationFormats::JSON)?;
        let rpy = ReplyEvent::new_reply(
            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );

        let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(&rpy.encode()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn get_state_for_prefix(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        self.event_storage.get_state(id)
    }

    pub fn process_notice(&self, notice: Notice) -> Result<(), Error> {
        process_notice(notice, &self.processor)
    }

    pub async fn process_op(&self, op: Op) -> Result<Option<PossibleResponse>, ActorError> {
        match op {
            Op::Query(SignedQueryMessage::KelQuery(qry)) => Ok(self.process_query(qry).await?),
            Op::Query(SignedQueryMessage::MailboxQuery(_qry)) => todo!(),
            Op::Reply(rpy) => {
                self.process_reply(rpy)?;
                Ok(None)
            }
            Op::Exchange(_exn) => Ok(None),
        }
    }

    pub async fn process_query(
        &self,
        qry: SignedKelQuery,
    ) -> Result<Option<PossibleResponse>, ActorError> {
        let cid = qry
            .signature
            .get_signer()
            .ok_or(ActorError::MissingSignerId)?;
        if !self.check_role(&cid)? {
            return Err(ActorError::MissingRole {
                id: cid.clone(),
                role: Role::Watcher,
            });
        }

        // Check signature
        let signature = qry.signature;
        let ver_result = signature.verify(
            &qry.query.encode().map_err(|_e| Error::VersionError)?,
            &self.event_storage,
        )?;

        if !ver_result {
            return Err(SignedQueryError::InvalidSignature.into());
        };

        // Check if we need to update state from witnesses
        match &qry.query.get_route() {
            QueryRoute::Logs {
                reply_route: _,
                args,
            } => {
                let local_state = self.get_state_for_prefix(&args.i);
                let needs_update = match (local_state, args.s, args.limit) {
                    (Some(state), Some(sn), Some(limit)) if sn + limit - 1 <= state.sn => false,
                    (Some(state), Some(sn), None) if sn <= state.sn => false,
                    _ => true,
                };

                if needs_update {
                    let id_to_update = qry.query.get_prefix();
                    // Send update request and await its completion with a timeout.
                    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
                    self.tx
                        .send(UpdateRequest {
                            id: id_to_update.clone(),
                            completion: Some(done_tx),
                        })
                        .await
                        .map_err(|_e| {
                            ActorError::GeneralError("Internal watcher error".to_string())
                        })?;

                    // Wait up to 10 seconds for the update to complete.
                    match tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        done_rx,
                    )
                    .await
                    {
                        Ok(Ok(Ok(()))) => {
                            // Update succeeded, check if we now have the data
                            let updated_state = self.get_state_for_prefix(&args.i);
                            let still_missing = match (updated_state, args.s, args.limit) {
                                (Some(state), Some(sn), Some(limit))
                                    if sn + limit - 1 <= state.sn =>
                                {
                                    false
                                }
                                (Some(state), Some(sn), None) if sn <= state.sn => false,
                                (None, _, _) => true,
                                _ => true,
                            };
                            if still_missing {
                                return Err(ActorError::NotFound(id_to_update));
                            }
                        }
                        Ok(Ok(Err(e))) => {
                            tracing::warn!(error = %e, "KEL update failed");
                            return Err(ActorError::NotFound(id_to_update));
                        }
                        Ok(Err(_)) => {
                            // Completion channel dropped — update task died
                            return Err(ActorError::NotFound(id_to_update));
                        }
                        Err(_) => {
                            // Timeout
                            tracing::warn!(prefix = %id_to_update, "KEL update timed out");
                            return Err(ActorError::NotFound(id_to_update));
                        }
                    }
                }
            }
            QueryRoute::Ksn {
                reply_route: _,
                args,
            } => {
                let local_state = self.get_state_for_prefix(&args.i);
                match (local_state, args.s) {
                    (Some(state), Some(sn)) if sn <= state.sn => {}
                    _ => {
                        // query watcher and return info, that it's not ready
                        let _ = self.update_local_kel(&qry.query.get_prefix()).await;
                    }
                };
            }
        }

        let response =
            match keri_core::actor::process_query(qry.query.get_route(), &self.event_storage) {
                Ok(reply) => reply,
                Err(QueryError::UnknownId { id }) => {
                    return Err(ActorError::NoIdentState { prefix: id })
                }
                Err(e) => {
                    return Err(ActorError::GeneralError(e.to_string()));
                }
            };

        match response {
            ReplyType::Ksn(ksn) => {
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    HashFunctionCode::Blake3_256,
                    SerializationFormats::JSON,
                );

                let signature = SelfSigningPrefix::Ed25519Sha512(self.signer.sign(&rpy.encode()?)?);
                let reply = SignedReply::new_nontrans(rpy, self.prefix.clone(), signature);
                Ok(Some(PossibleResponse::Ksn(reply)))
            }
            ReplyType::Kel(msgs) => Ok(Some(PossibleResponse::Kel(msgs))),
            ReplyType::Mbx(mbx) => Ok(Some(PossibleResponse::Mbx(mbx))),
        }
    }

    pub async fn update_local_kel(&self, id: &IdentifierPrefix) -> Result<(), ActorError> {
        // Query all witnesses for the latest KSN and get the highest reported SN.
        let witness_sn = self.query_state(id).await?;

        // Compare against locally stored KEL state.
        let local_sn = self
            .event_storage
            .get_state(id)
            .map(|s| s.sn)
            .unwrap_or(0);

        if local_sn < witness_sn {
            // We are behind — fetch the missing KEL events from witnesses.
            self.forward_query_from(id, local_sn).await?;
        } else {
            // Even if SN matches, check if there are escrowed replies waiting
            // for events we may have missed (e.g. receipts, delegations).
            let escrowed_replies = self
                .reply_escrow
                .get_all(&id)
                .into_iter()
                .flatten()
                .collect_vec();

            if !escrowed_replies.is_empty() {
                self.forward_query_from(id, local_sn).await?;
            }
        }

        Ok(())
    }

    pub fn process_reply(&self, reply: SignedReply) -> Result<(), Error> {
        process_reply(
            reply,
            &self.oobi_manager,
            &self.processor,
            &self.event_storage,
        )?;
        Ok(())
    }

    /// Forward query to registered witnesses and save its response to mailbox.
    /// Fetches events starting from `from_sn` to avoid re-fetching the entire KEL.
    pub(crate) async fn forward_query_from(
        &self,
        id: &IdentifierPrefix,
        from_sn: u64,
    ) -> Result<(), ActorError> {
        let witnesses = self.get_witnesses_for_prefix(&id)?;
        for witness in witnesses {
            let witness_id = IdentifierPrefix::Basic(witness);
            let route = QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    i: id.clone(),
                    s: if from_sn > 0 { Some(from_sn) } else { None },
                    src: Some(witness_id.clone()),
                    limit: None,
                },
            };

            let qry = QueryEvent::new_query(
                route,
                SerializationFormats::JSON,
                HashFunctionCode::Blake3_256,
            );
            // Create a new signed message
            let sigs = SelfSigningPrefix::Ed25519Sha512(self.signer.sign(qry.encode()?)?);
            let signed_qry = SignedKelQuery::new_nontrans(qry.clone(), self.prefix.clone(), sigs);

            let resp = self
                .send_query_to(
                    witness_id.clone(),
                    keri_core::oobi::Scheme::Http,
                    signed_qry,
                )
                .await;

            let resp = match resp {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        witness = %witness_id,
                        prefix = %id,
                        error = %e,
                        "Failed to fetch KEL from witness, trying next"
                    );
                    continue;
                }
            };

            match resp {
                PossibleResponse::Ksn(rpy) => {
                    self.process_reply(rpy)?;
                }
                PossibleResponse::Kel(msgs) => {
                    for msg in msgs {
                        if let Message::Notice(notice) = msg {
                            self.process_notice(notice.clone())?;
                            if let Notice::Event(evt) = notice {
                                self.event_storage.add_mailbox_reply(evt)?;
                            }
                        }
                    }
                }
                PossibleResponse::Mbx(_mbx) => {
                    tracing::error!("Unexpected MBX response from witness {}", witness_id);
                }
            }
        }

        Ok(())
    }

    /// Query all witnesses about KSN for given prefix.
    /// Returns the highest SN reported by any witness.
    pub(crate) async fn query_state(&self, prefix: &IdentifierPrefix) -> Result<u64, ActorError> {
        let wits_id = self.get_witnesses_for_prefix(&prefix)?;
        let results: Vec<Result<u64, ActorError>> = join_all(wits_id.into_iter().map(|id| {
            let id = IdentifierPrefix::Basic(id);
            self.ksn_update(&prefix, id)
        }))
        .await;

        let mut max_sn: u64 = 0;
        let mut any_success = false;
        for result in results {
            match result {
                Ok(sn) => {
                    any_success = true;
                    if sn > max_sn {
                        max_sn = sn;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        prefix = %prefix,
                        error = %e,
                        "Failed to get KSN from witness"
                    );
                }
            }
        }

        if !any_success && max_sn == 0 {
            // Fall back to local state if all witnesses failed
            max_sn = self
                .event_storage
                .get_state(prefix)
                .map(|s| s.sn)
                .unwrap_or(0);
        }

        Ok(max_sn)
    }

    pub(crate) async fn tel_update(
        &self,
        about_ri: &IdentifierPrefix,
        about_vc_id: &IdentifierPrefix,
        wit_id: IdentifierPrefix,
    ) -> Result<(), ActorError> {
        let location = self.oobi_manager.get_loc_scheme(&wit_id)?[0]
            .clone()
            .data
            .data;
        let loc = if let ReplyRoute::LocScheme(loc) = location {
            loc
        } else {
            return Err(ActorError::WrongReplyRoute);
        };
        let route = TelQueryRoute::Tels {
            reply_route: "".into(),
            args: TelQueryArgs {
                i: Some(about_vc_id.clone()),
                ri: Some(about_ri.clone()),
            },
        };
        let env = Timestamped::new(route);
        let qry = KeriEvent::new(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            env,
        );

        // sign message by watcher
        let signature = SelfSigningPrefix::Ed25519Sha512(
            self.signer.sign(
                serde_json::to_vec(&qry)
                    .map_err(|e| keri_core::error::Error::SerializationError(e.to_string()))?,
            )?,
        );
        let query = SignedTelQuery::new_nontrans(qry, self.prefix.clone(), signature);
        let resp = self
            .tel_transport
            .send_query(query, loc)
            .await
            .map_err(|e| ActorError::GeneralError(e.to_string()))?;
        self.tel_to_forward
            .save(about_ri, about_vc_id, resp)
            .map_err(|e| ActorError::GeneralError(e.to_string()))?;
        Ok(())
    }

    /// Query a specific witness for the KSN of a prefix.
    /// Returns the SN reported by the witness.
    async fn ksn_update(
        &self,
        about_id: &IdentifierPrefix,
        wit_id: IdentifierPrefix,
    ) -> Result<u64, ActorError> {
        let query_args = LogsQueryArgs {
            i: about_id.clone(),
            s: None,
            src: Some(wit_id.clone()),
            limit: None,
        };

        let qry = QueryEvent::new_query(
            QueryRoute::Ksn {
                args: query_args,
                reply_route: String::from(""),
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        );

        // sign message by watcher
        let signature = SelfSigningPrefix::Ed25519Sha512(
            self.signer.sign(
                serde_json::to_vec(&qry)
                    .map_err(|e| keri_core::error::Error::SerializationError(e.to_string()))?,
            )?,
        );
        let query = SignedKelQuery::new_nontrans(qry, self.prefix.clone(), signature);

        let start = std::time::Instant::now();
        let resp = match self.send_query_to(wit_id.clone(), Scheme::Http, query).await {
            Ok(r) => r,
            Err(e) => {
                self.health_tracker
                    .record_failure(&wit_id, e.to_string());
                return Err(e);
            }
        };

        let resp = match resp {
            PossibleResponse::Ksn(ksn) => ksn,
            e => {
                let err = ActorError::UnexpectedResponse(e.to_string());
                self.health_tracker
                    .record_failure(&wit_id, err.to_string());
                return Err(err);
            }
        };

        // Extract the SN from the KSN reply before processing it.
        let route = resp.reply.get_route();
        let sn = match route {
            ReplyRoute::Ksn(_, ksn) => ksn.state.sn,
            _ => 0,
        };

        self.process_reply(resp)?;
        self.health_tracker
            .record_success(&wit_id, start.elapsed());
        Ok(sn)
    }

    /// Get witnesses for prefix
    fn get_witnesses_for_prefix(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, ActorError> {
        let wit_id = self
            .get_state_for_prefix(&id)
            .map(|state| state.witness_config.witnesses)
            .ok_or(ActorError::NoIdentState { prefix: id.clone() })?;
        Ok(wit_id)
    }

    /// Query roles in oobi manager to check if controller with given ID is allowed to communicate with us.
    fn check_role(&self, cid: &IdentifierPrefix) -> Result<bool, OobiError> {
        Ok(self
            .oobi_manager
            .get_end_role(cid, Role::Watcher)?
            .unwrap_or_default()
            .iter()
            .filter_map(|reply| {
                if let ReplyRoute::EndRoleAdd(role) = reply.reply.get_route() {
                    Some(role)
                } else {
                    None
                }
            })
            .any(|role| {
                role.cid == *cid && role.eid == IdentifierPrefix::Basic(self.prefix.clone())
            }))
    }

    pub async fn process_ops(&self, ops: Vec<Op>) -> Result<Vec<PossibleResponse>, ActorError> {
        let mut results = Vec::new();
        for op in ops {
            let result = self.process_op(op).await?;
            if let Some(response) = result {
                results.push(response);
            }
        }
        Ok(results)
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>, ActorError> {
        let oobis = self.oobi_manager.get_loc_scheme(id)?;
        if oobis.is_empty() {
            Err(ActorError::NoLocation { id: id.clone() })
        } else {
            Ok(oobis
                .iter()
                .filter_map(|oobi_to_sing| match &oobi_to_sing.data.data {
                    ReplyRoute::LocScheme(loc) => Some(loc.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>())
        }
    }

    pub async fn send_query_to(
        &self,
        wit_id: IdentifierPrefix,
        scheme: Scheme,
        query: SignedKelQuery,
    ) -> Result<PossibleResponse, ActorError> {
        let locs = self.get_loc_schemas(&wit_id)?;
        let loc = locs.into_iter().find(|loc| loc.scheme == scheme);

        let loc = match loc {
            Some(loc) => loc,
            None => return Err(ActorError::NoLocation { id: wit_id }),
        };

        let response = self
            .transport
            .send_query(
                loc,
                keri_core::query::query_event::SignedQueryMessage::KelQuery(query),
            )
            .await?;

        Ok(response)
    }
}
