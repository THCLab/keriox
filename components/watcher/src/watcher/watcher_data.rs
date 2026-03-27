use std::{fs::File, sync::Arc};

use futures::future::join_all;
use itertools::Itertools;
use keri_core::actor::possible_response::PossibleResponse;
use keri_core::database::redb::RedbError;
use keri_core::error::Error;
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
    oobi_manager::OobiManager,
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

use super::{config::WatcherConfig, tel_providing::TelToForward};

pub struct WatcherData {
    pub address: url::Url,
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor<RedbDatabase>,
    pub event_storage: Arc<EventStorage<RedbDatabase>>,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn WatcherTelTransport + Send + Sync>,
    /// Watcher will update KEL of the identifiers that have been sent to this channel.
    tx: Sender<IdentifierPrefix>,
    /// Watcher will update TEL of the identifiers (registry_id, vc_id) that have been sent to this channel.
    pub tel_tx: Sender<(IdentifierPrefix, IdentifierPrefix)>,
    pub(super) tel_to_forward: Arc<TelToForward>,
    reply_escrow: Arc<ReplyEscrow<RedbDatabase>>,
}

impl WatcherData {
    pub fn new(
        config: WatcherConfig,
        tx: Sender<IdentifierPrefix>,
        tel_tx: Sender<(IdentifierPrefix, IdentifierPrefix)>,
    ) -> Result<Arc<Self>, ActorError> {
        let WatcherConfig {
            public_address,
            db_path,
            priv_key,
            transport,
            escrow_config,
            tel_storage_path,
            tel_transport,
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

        let oobi_manager = OobiManager::new(events_db.clone());

        let (notification_bus, _) = default_escrow_bus(events_db.clone(), escrow_config);
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
                match (local_state, args.s, args.limit) {
                    (Some(state), Some(sn), Some(limit)) if sn + limit - 1 <= state.sn => {
                        // KEL is already in database
                    }
                    (Some(state), Some(sn), None) if sn <= state.sn => {
                        // KEL is already in database
                    }
                    (Some(_state), None, None) => {
                        // Check for updates.
                        let id_to_update = qry.query.get_prefix();
                        self.tx.send(id_to_update.clone()).await.map_err(|_e| {
                            ActorError::GeneralError("Internal watcher error".to_string())
                        })?;
                    }
                    _ => {
                        // query watcher and return info, that it's not ready
                        let id_to_update = qry.query.get_prefix();
                        self.tx.send(id_to_update.clone()).await.map_err(|_e| {
                            ActorError::GeneralError("Internal watcher error".to_string())
                        })?;
                        return Err(ActorError::NotFound(id_to_update));
                    }
                };
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
        // Update latest state for prefix
        let _ = self.query_state(id).await;

        let escrowed_replies = self
            .reply_escrow
            .get_all(&id)
            .into_iter()
            .flatten()
            .collect_vec();

        if !escrowed_replies.is_empty() {
            // If there is an escrowed reply it means we don't have the most recent data.
            // In this case forward the query to witness.
            self.forward_query(id).await?;
        };
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
    async fn forward_query(&self, id: &IdentifierPrefix) -> Result<(), ActorError> {
        let witnesses = self.get_witnesses_for_prefix(&id)?;
        for witness in witnesses {
            let witness_id = IdentifierPrefix::Basic(witness);
            let route = QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    i: id.clone(),
                    s: None,
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
                .await?;

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
                    panic!("Unexpected response type MBX");
                }
            }
        }

        Ok(())
    }

    /// Query witness about KSN for given prefix and save its response to db.
    /// Returns ID of witness that responded.
    async fn query_state(&self, prefix: &IdentifierPrefix) -> Result<(), ActorError> {
        let wits_id = self.get_witnesses_for_prefix(&prefix)?;
        let _r: Vec<Result<_, _>> = join_all(wits_id.into_iter().map(|id| {
            let id = IdentifierPrefix::Basic(id);

            self.ksn_update(&prefix, id)
        }))
        .await;

        Ok(())
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

    async fn ksn_update(
        &self,
        about_id: &IdentifierPrefix,
        wit_id: IdentifierPrefix,
    ) -> Result<(), ActorError> {
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
        let resp = self.send_query_to(wit_id, Scheme::Http, query).await?;

        let resp = match resp {
            PossibleResponse::Ksn(ksn) => ksn,
            e => return Err(ActorError::UnexpectedResponse(e.to_string())),
        };

        self.process_reply(resp)?;
        Ok(())
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
    fn check_role(&self, cid: &IdentifierPrefix) -> Result<bool, RedbError> {
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
