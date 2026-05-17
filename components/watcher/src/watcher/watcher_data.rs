use std::{fs::File, sync::Arc, time::Instant};

use futures::future::join_all;
use futures::stream::{FuturesUnordered, StreamExt};
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
    oobi::Role,
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
    oobi_manager::{storage::OobiStorageBackend, OobiManager},
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
    kel_update_timeout: std::time::Duration,
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
            kel_update_timeout,
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

        let (notification_bus, _escrows) =
            default_escrow_bus(events_db.clone(), escrow_config, None);
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
            kel_update_timeout,
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

                    // Wait for the update to complete, bounded by the
                    // configured timeout. A client verifying an unknown AID
                    // generally prefers a fast "not yet" + retry over a
                    // long block here.
                    match tokio::time::timeout(self.kel_update_timeout, done_rx).await {
                        Ok(Ok(Ok(()))) => {
                            // Update succeeded, check if we now have the data.
                            let updated_state = self.get_state_for_prefix(&args.i);
                            if logs_query_still_missing(
                                updated_state.as_ref().map(|s| s.sn),
                                args.s,
                                args.limit,
                            ) {
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
                            tracing::warn!(
                                prefix = %id_to_update,
                                timeout_ms = self.kel_update_timeout.as_millis() as u64,
                                "KEL update timed out"
                            );
                            metrics::counter!(
                                crate::metrics::names::KEL_FETCH_TOTAL,
                                "outcome" => "timeout"
                            )
                            .increment(1);
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
        let local_sn = self.event_storage.get_state(id).map(|s| s.sn).unwrap_or(0);

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
    ///
    /// Witnesses are queried in health-priority order: known-healthy ones
    /// first, sorted by EMA response time (so the historically fastest
    /// goes first), then degraded ones as a fallback. Queries fan out via
    /// `FuturesUnordered`, and we return as soon as a response gives us
    /// the KEL covering `from_sn` — any still-pending requests are
    /// dropped, which `reqwest` translates into TCP-level cancellation.
    /// This is the change that stops the user-facing verification flow
    /// from waiting on the slowest witness.
    #[tracing::instrument(skip(self), fields(prefix = %id, from_sn))]
    pub(crate) async fn forward_query_from(
        &self,
        id: &IdentifierPrefix,
        from_sn: u64,
    ) -> Result<(), ActorError> {
        let _outer = crate::metrics::LatencyTimer::new(
            crate::metrics::names::KEL_FETCH_SECONDS,
            vec![("outcome", "completed".to_string())],
        );
        let _inflight = crate::metrics::InflightGuard::enter();
        metrics::counter!(
            crate::metrics::names::KEL_FETCH_TOTAL,
            "outcome" => "completed"
        )
        .increment(1);
        let witnesses_basic = self.get_witnesses_for_prefix(&id)?;
        let witness_ips: Vec<IdentifierPrefix> = witnesses_basic
            .into_iter()
            .map(IdentifierPrefix::Basic)
            .collect();
        let (ordered, degraded_start) = self.health_tracker.priority_order(&witness_ips);

        let mut futs = FuturesUnordered::new();
        for (rank, witness_id) in ordered.iter().enumerate() {
            let witness_id = witness_id.clone();
            let id_inner = id.clone();
            let route = QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    i: id_inner.clone(),
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
            let qry_bytes = qry.encode().map_err(ActorError::from)?;
            let sigs = SelfSigningPrefix::Ed25519Sha512(
                self.signer.sign(qry_bytes).map_err(ActorError::from)?,
            );
            let signed_qry =
                SignedKelQuery::new_nontrans(qry.clone(), self.prefix.clone(), sigs);
            futs.push(async move {
                let started = Instant::now();
                let _timer = crate::metrics::LatencyTimer::new(
                    crate::metrics::names::WITNESS_QUERY_SECONDS,
                    vec![
                        ("witness_id", witness_id.to_string()),
                        ("kind", "logs".to_string()),
                    ],
                );
                let resp = self
                    .send_query_to(witness_id.clone(), signed_qry)
                    .await;
                (witness_id, rank, started.elapsed(), resp)
            });
        }

        let mut got_any_success = false;
        while let Some((witness_id, rank, elapsed, resp)) = futs.next().await {
            match resp {
                Ok(r) => {
                    got_any_success = true;
                    self.health_tracker.record_success(&witness_id, elapsed);
                    let satisfied = match r {
                        PossibleResponse::Ksn(rpy) => {
                            self.process_reply(rpy)?;
                            // KSN reply alone doesn't tell us we have the KEL events
                            // up to from_sn; only Kel replies do. Keep going.
                            false
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
                            // Did this fill the requested window?
                            self.event_storage
                                .get_state(id)
                                .map(|s| s.sn >= from_sn)
                                .unwrap_or(false)
                        }
                        PossibleResponse::Mbx(_mbx) => {
                            tracing::error!(
                                "Unexpected MBX response from witness {}",
                                witness_id
                            );
                            false
                        }
                    };
                    if satisfied {
                        tracing::debug!(
                            witness = %witness_id,
                            rank,
                            healthy_pool = degraded_start,
                            "KEL covered by witness; returning early"
                        );
                        // Drop `futs` to cancel the rest.
                        return Ok(());
                    }
                }
                Err(e) => {
                    self.health_tracker
                        .record_failure(&witness_id, e.to_string());
                    metrics::counter!(
                        crate::metrics::names::WITNESS_QUERY_FAILURES_TOTAL,
                        "witness_id" => witness_id.to_string(),
                        "kind" => "logs"
                    )
                    .increment(1);
                    tracing::warn!(
                        witness = %witness_id,
                        prefix = %id,
                        error = %e,
                        rank,
                        "Failed to fetch KEL from witness"
                    );
                }
            }
        }

        if !got_any_success {
            tracing::warn!(prefix = %id, "all witnesses failed for KEL fetch");
        }
        Ok(())
    }

    /// Query all witnesses about KSN for given prefix.
    /// Returns the highest SN reported by any witness.
    #[tracing::instrument(skip(self), fields(prefix = %prefix))]
    pub(crate) async fn query_state(&self, prefix: &IdentifierPrefix) -> Result<u64, ActorError> {
        let wits_id = self.get_witnesses_for_prefix(&prefix)?;
        // Use only healthy witnesses for the parallel fan-out; if none
        // qualify, fall back to all of them (better to probe a degraded
        // witness than return stale local state forever).
        let witness_ips: Vec<IdentifierPrefix> = wits_id
            .into_iter()
            .map(IdentifierPrefix::Basic)
            .collect();
        let (ordered, degraded_start) = self.health_tracker.priority_order(&witness_ips);
        let to_query: Vec<IdentifierPrefix> = if degraded_start == 0 {
            ordered
        } else {
            ordered.into_iter().take(degraded_start).collect()
        };
        let results: Vec<Result<u64, ActorError>> = join_all(to_query.into_iter().map(|id| {
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
                    // `ActorError::TransportError(_)`'s Display collapses
                    // to "network request failed", which is the actual
                    // user-visible error for ksn_update problems. Walk
                    // the source chain and dump Debug so operators can
                    // distinguish DNS / TLS / non-2xx / unparseable body
                    // without a debugger.
                    let mut chain = format!("{e}");
                    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(&e);
                    while let Some(inner) = src {
                        chain.push_str(" -> ");
                        chain.push_str(&format!("{inner}"));
                        src = inner.source();
                    }
                    tracing::warn!(
                        prefix = %prefix,
                        error = %chain,
                        error_debug = ?e,
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
        let loc = self.latest_loc_scheme(&wit_id)?;
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
    #[tracing::instrument(skip(self), fields(prefix = %about_id, witness = %wit_id))]
    async fn ksn_update(
        &self,
        about_id: &IdentifierPrefix,
        wit_id: IdentifierPrefix,
    ) -> Result<u64, ActorError> {
        let _per_witness = crate::metrics::LatencyTimer::new(
            crate::metrics::names::WITNESS_QUERY_SECONDS,
            vec![
                ("witness_id", wit_id.to_string()),
                ("kind", "ksn".to_string()),
            ],
        );
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
        let resp = match self
            .send_query_to(wit_id.clone(), query)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.health_tracker.record_failure(&wit_id, e.to_string());
                return Err(e);
            }
        };

        let resp = match resp {
            PossibleResponse::Ksn(ksn) => ksn,
            e => {
                let err = ActorError::UnexpectedResponse(e.to_string());
                self.health_tracker.record_failure(&wit_id, err.to_string());
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
        self.health_tracker.record_success(&wit_id, start.elapsed());
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

    pub async fn send_query_to(
        &self,
        wit_id: IdentifierPrefix,
        query: SignedKelQuery,
    ) -> Result<PossibleResponse, ActorError> {
        let loc = self.latest_loc_scheme(&wit_id)?;

        let response = self
            .transport
            .send_query(
                loc,
                keri_core::query::query_event::SignedQueryMessage::KelQuery(query),
            )
            .await?;

        Ok(response)
    }

    /// Pick the freshest `LocationScheme` reply for `eid`, regardless
    /// of scheme. The OOBI store keeps every signed loc reply we ever
    /// ingested — including obsolete ones from before a witness's
    /// scheme migration — and the older entries sort first in storage
    /// order. KERI's bada logic already says the newest `dt` wins;
    /// callers that previously hardcoded `Scheme::Http` therefore
    /// silently selected stale endpoints. Use this helper from any
    /// path that wants "current" rather than "specific scheme".
    pub(crate) fn latest_loc_scheme(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<LocationScheme, ActorError> {
        let replies = self.oobi_manager.get_loc_scheme(eid)?;
        if replies.is_empty() {
            return Err(ActorError::NoLocation { id: eid.clone() });
        }
        let latest = replies
            .into_iter()
            .max_by_key(|r| r.get_timestamp())
            .ok_or_else(|| ActorError::NoLocation { id: eid.clone() })?;
        match latest.data.data {
            ReplyRoute::LocScheme(loc) => Ok(loc),
            _ => Err(ActorError::WrongReplyRoute),
        }
    }
}

/// Decide whether a watcher should answer a `logs` query with
/// `NotFound` because its local store is insufficient.
///
/// Inputs are the watcher's current head sequence number for the
/// queried prefix (`local_head_sn`, `None` when the prefix is unknown)
/// and the query's optional sequence-floor (`args.s`) and limit
/// (`args.limit`).
///
/// A `logs` query without `s` is a full-log request: the caller wants
/// every event we know about the prefix and `process_query` will pull
/// them from `event_storage::get_kel_messages_with_receipts_all`. So
/// as long as we have any local state at all we are not "missing"
/// anything answerable — returning `NotFound` here would silently
/// fail every full-log query even when the watcher had been seeded.
/// That was the original bug: the match's `_ => true` catch-all hit
/// every `(Some(_), None, _)` and the controller saw
/// `KELNotFound` despite the watcher's store containing the icp +
/// receipts pushed by the controller seconds earlier.
pub(crate) fn logs_query_still_missing(
    local_head_sn: Option<u64>,
    args_s: Option<u64>,
    args_limit: Option<u64>,
) -> bool {
    match (local_head_sn, args_s, args_limit) {
        // Range query: we satisfy it if our head reaches sn+limit-1.
        (Some(state_sn), Some(sn), Some(limit)) => sn + limit - 1 > state_sn,
        // Open-ended-from-sn query: satisfied as long as head reaches sn.
        (Some(state_sn), Some(sn), None) => sn > state_sn,
        // Full-log query (no floor): any local state means we have
        // something to return.
        (Some(_), None, _) => false,
        // No state at all → genuinely missing.
        (None, _, _) => true,
    }
}

#[cfg(test)]
mod still_missing_tests {
    use super::logs_query_still_missing;

    #[test]
    fn full_log_query_with_local_state_is_not_missing() {
        // Regression: previously the catch-all `_ => true` hit
        // `(Some(_), None, None)` and the controller saw KELNotFound
        // for every `query_full_log` call, even when the watcher had
        // the peer's icp + receipts in its event store.
        assert!(!logs_query_still_missing(Some(0), None, None));
        assert!(!logs_query_still_missing(Some(5), None, None));
        assert!(!logs_query_still_missing(Some(0), None, Some(10)));
    }

    #[test]
    fn no_local_state_is_missing() {
        assert!(logs_query_still_missing(None, None, None));
        assert!(logs_query_still_missing(None, Some(0), None));
        assert!(logs_query_still_missing(None, Some(3), Some(5)));
    }

    #[test]
    fn ranged_query_compares_against_local_head() {
        // sn..(sn+limit-1) inclusive must be within the head.
        assert!(!logs_query_still_missing(Some(4), Some(0), Some(5))); // 0..=4 ≤ 4
        assert!(logs_query_still_missing(Some(3), Some(0), Some(5))); //  0..=4 > 3
        assert!(!logs_query_still_missing(Some(10), Some(3), Some(2))); // 3..=4 ≤ 10
    }

    #[test]
    fn open_from_sn_query_compares_floor_against_head() {
        assert!(!logs_query_still_missing(Some(5), Some(0), None));
        assert!(!logs_query_still_missing(Some(5), Some(5), None));
        assert!(logs_query_still_missing(Some(4), Some(5), None));
    }
}
