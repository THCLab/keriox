use std::{path::PathBuf, sync::Arc};

use async_std::channel::{unbounded, Receiver, Sender};
use futures::future::join_all;
use itertools::Itertools;
use keri_core::{
    actor::{
        error::ActorError, parse_notice_stream, parse_query_stream, parse_reply_stream, prelude::*,
        simple_controller::PossibleResponse, QueryError, SignedQueryError,
    },
    database::{escrow::EscrowDb, DbError},
    error::Error,
    event_message::signed_event_message::{Message, Notice, Op},
    oobi::{error::OobiError, EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::{
        escrow::{default_escrow_bus, EscrowConfig, ReplyEscrow},
        notification::JustNotification,
    },
    query::{
        query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery, SignedQueryMessage},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
    transport::{default::DefaultTransport, Transport},
};

pub struct WatcherData {
    address: url::Url,
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor,
    event_storage: EventStorage,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    transport: Box<dyn Transport + Send + Sync>,
    /// Watcher will update KEL of the identifiers that have been sent to this channel.
    tx: Sender<IdentifierPrefix>,
}

pub struct WatcherConfig {
    pub public_address: url::Url,
    pub db_path: PathBuf,
    pub priv_key: Option<String>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub escrow_config: EscrowConfig,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            public_address: url::Url::parse("http://localhost:3236").unwrap(),
            db_path: PathBuf::from("db"),
            priv_key: None,
            transport: Box::new(DefaultTransport::new()),
            escrow_config: EscrowConfig::default(),
        }
    }
}

impl WatcherData {
    pub fn new(config: WatcherConfig, tx: Sender<IdentifierPrefix>) -> Result<Arc<Self>, Error> {
        let WatcherConfig {
            public_address,
            db_path,
            priv_key,
            transport,
            escrow_config,
        } = config;

        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );

        let db = Arc::new(SledEventDatabase::new(db_path.clone())?);

        let escrow_db = {
            let mut path = db_path.clone();
            path.push("escrow");
            Arc::new(EscrowDb::new(path)?)
        };

        let oobi_manager = {
            let mut path = db_path;
            path.push("oobi");
            OobiManager::new(&path)
        };

        let (mut notification_bus, _) = default_escrow_bus(db.clone(), escrow_db, escrow_config);
        notification_bus.register_observer(
            Arc::new(ReplyEscrow::new(db.clone())),
            vec![
                JustNotification::KeyEventAdded,
                JustNotification::KsnOutOfOrder,
            ],
        );

        let prefix = BasicPrefix::Ed25519NT(signer.public_key()); // watcher uses non transferable key
        let processor = BasicProcessor::new(db.clone(), Some(notification_bus));

        let storage = EventStorage::new(db);

        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(prefix.clone()),
            public_address.scheme().parse().unwrap(),
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
        });
        Ok(watcher.clone())
    }

    /// Get location scheme from OOBI manager and sign it.
    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Vec<SignedReply>, ActorError> {
        Ok(match self.oobi_manager.get_loc_scheme(eid)? {
            Some(oobis_to_sign) => oobis_to_sign
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.encode().unwrap())?;
                    Ok(SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.prefix.clone(),
                        SelfSigningPrefix::Ed25519Sha512(signature),
                    ))
                })
                .collect::<Result<_, Error>>()?,
            None => return Err(ActorError::NoLocation { id: eid.clone() }),
        })
    }

    pub fn get_end_role_for_id(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Vec<SignedReply>, ActorError> {
        self.oobi_manager
            .get_end_role(&cid, role)
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

    fn process_notice(&self, notice: Notice) -> Result<(), Error> {
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

    async fn process_query(
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
                match (local_state, args.s) {
                    (Some(state), Some(sn)) if sn <= state.sn => {
                        // KEL is already in database
                    }
                    _ => {
                        // query watcher and return info, that it's not ready
                        let id_to_update = qry.query.get_prefix();
                        self.tx.send(id_to_update.clone()).await.unwrap();
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
            .event_storage
            .db
            .get_escrowed_replys(&id)
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

    async fn ksn_update(
        &self,
        about_id: &IdentifierPrefix,
        wit_id: IdentifierPrefix,
    ) -> Result<(), ActorError> {
        let query_args = LogsQueryArgs {
            i: about_id.clone(),
            s: None,
            src: Some(wit_id.clone()),
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

    /// Get witnesses for prefix and choose one randomly
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
    fn check_role(&self, cid: &IdentifierPrefix) -> Result<bool, DbError> {
        Ok(self
            .oobi_manager
            .get_end_role(cid, Role::Watcher)?
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
        Ok(match self.oobi_manager.get_loc_scheme(id)? {
            Some(oobis_to_sign) => oobis_to_sign
                .iter()
                .filter_map(|oobi_to_sing| match &oobi_to_sing.data.data {
                    ReplyRoute::LocScheme(loc) => Some(loc.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>(),
            None => return Err(ActorError::NoLocation { id: id.clone() }),
        })
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

pub struct Watcher {
    pub(crate) watcher_data: Arc<WatcherData>,
    recv: Receiver<IdentifierPrefix>,
}

impl Watcher {
    pub fn new(config: WatcherConfig) -> Result<Self, Error> {
        let (tx, rx) = unbounded();
        Ok(Watcher {
            watcher_data: WatcherData::new(config, tx)?,
            recv: rx,
        })
    }

    pub fn prefix(&self) -> BasicPrefix {
        self.watcher_data.prefix.clone()
    }

    pub fn signed_location(&self, eid: &IdentifierPrefix) -> Result<Vec<SignedReply>, ActorError> {
        self.watcher_data.get_loc_scheme_for_id(eid)
    }

    pub async fn process_update_requests(&self) {
        if let Ok(received) = self.recv.try_recv() {
            let _ = self.watcher_data.update_local_kel(&received).await;
        }
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
                .request_end_role(loc, er.cid, er.role, er.eid)
                .await?;
            for m in oobis {
                match m {
                    Message::Op(op) => {
                        self.watcher_data.process_op(op).await?;
                    }
                    Message::Notice(not) => {
                        self.watcher_data.process_notice(not)?;
                    }
                }
            }
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
}
