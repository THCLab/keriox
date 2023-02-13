use std::{path::PathBuf, sync::Arc};

use itertools::Itertools;
use keri::{
    actor::{
        error::ActorError, parse_notice_stream, parse_query_stream, parse_reply_stream, prelude::*,
        simple_controller::PossibleResponse,
    },
    database::{escrow::EscrowDb, DbError},
    error::Error,
    event_message::signed_event_message::{Message, Notice, Op},
    oobi::{error::OobiError, EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::escrow::{default_escrow_bus, EscrowConfig},
    query::{
        query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
    transport::{default::DefaultTransport, Transport},
};
use rand::prelude::SliceRandom;

pub struct WatcherData {
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor,
    event_storage: EventStorage,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    transport: Box<dyn Transport + Send + Sync>,
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
    pub fn new(config: WatcherConfig) -> Result<Self, Error> {
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

        let (notification_bus, _) = default_escrow_bus(db.clone(), escrow_db, escrow_config);

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
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            prefix.clone(),
            SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.encode()?)?),
        );
        oobi_manager.save_oobi(&signed_reply)?;

        Ok(Self {
            prefix,
            processor,
            event_storage: storage,
            signer,
            oobi_manager,
            transport,
        })
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
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;

        let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(&rpy.encode()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn get_state_for_prefix(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.event_storage.get_state(id)
    }

    fn process_notice(&self, notice: Notice) -> Result<(), Error> {
        process_notice(notice, &self.processor)
    }

    pub async fn process_op(&self, op: Op) -> Result<Option<PossibleResponse>, ActorError> {
        match op {
            Op::Query(qry) => Ok(self.process_query(qry).await?),
            Op::Reply(rpy) => {
                self.process_reply(rpy)?;
                Ok(None)
            }
            Op::Exchange(_exn) => Ok(None),
        }
    }

    async fn process_query(
        &self,
        qry: SignedQuery,
    ) -> Result<Option<PossibleResponse>, ActorError> {
        let cid = qry.signer.clone();
        if !self.check_role(&cid)? {
            return Err(ActorError::MissingRole {
                id: cid.clone(),
                role: Role::Watcher,
            });
        }

        match &qry.query.data.data.route {
            QueryRoute::Ksn { .. } | QueryRoute::Log { .. } => {
                // Update latest state for prefix
                self.query_state(qry.query.get_prefix()).await?;

                let escrowed_replies = self
                    .event_storage
                    .db
                    .get_escrowed_replys(&qry.query.get_prefix())
                    .into_iter()
                    .flatten()
                    .collect_vec();

                if !escrowed_replies.is_empty() {
                    // If there is an escrowed reply it means we don't have the most recent data.
                    // In this case forward the query to witness.
                    self.forward_query(&qry).await?;
                    return Ok(None);
                }
            }
            QueryRoute::Mbx { .. } => {}
        }

        let response = process_signed_query(qry.clone(), &self.event_storage)?;

        match response {
            ReplyType::Ksn(ksn) => {
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;

                let signature = SelfSigningPrefix::Ed25519Sha512(self.signer.sign(&rpy.encode()?)?);
                let reply = SignedReply::new_nontrans(rpy, self.prefix.clone(), signature);
                Ok(Some(PossibleResponse::Ksn(reply)))
            }
            ReplyType::Kel(msgs) => Ok(Some(PossibleResponse::Kel(msgs))),
            ReplyType::Mbx(mbx) => Ok(Some(PossibleResponse::Mbx(mbx))),
        }
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

    /// Forward query to random registered witness and save its response to mailbox.
    async fn forward_query(&self, qry: &SignedQuery) -> Result<(), ActorError> {
        // Create a new signed message based on the received one
        let sigs = vec![IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(self.signer.sign(qry.query.encode()?)?),
            0,
        )];
        let qry = SignedQuery::new(
            qry.query.clone(),
            IdentifierPrefix::Basic(self.prefix.clone()),
            sigs,
        );

        let wit_id = self.get_witness_for_prefix(qry.query.get_prefix())?;

        // Send query to witness
        let resp = self
            .send_query_to(
                IdentifierPrefix::Basic(wit_id.clone()),
                keri::oobi::Scheme::Http,
                qry,
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

        Ok(())
    }

    /// Query witness about KSN for given prefix and save its response to db.
    /// Returns ID of witness that responded.
    async fn query_state(&self, prefix: IdentifierPrefix) -> Result<BasicPrefix, ActorError> {
        let query_args = QueryArgs {
            s: None,
            i: prefix.clone(),
            src: None,
        };

        let qry = QueryEvent::new_query(
            QueryRoute::Ksn {
                args: query_args,
                reply_route: String::from(""),
            },
            SerializationFormats::JSON,
            SelfAddressing::Blake3_256,
        )?;

        // sign message by watcher
        let signature = IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(
                (self.signer).sign(serde_json::to_vec(&qry).unwrap())?,
            ),
            0,
        );

        let query = SignedQuery::new(
            qry,
            IdentifierPrefix::Basic(self.prefix.clone()),
            vec![signature],
        );

        let wit_id = self.get_witness_for_prefix(prefix)?;

        let resp = self
            .send_query_to(IdentifierPrefix::Basic(wit_id.clone()), Scheme::Http, query)
            .await?;

        let resp = match resp {
            PossibleResponse::Ksn(ksn) => ksn,
            _ => panic!("Invalid response"),
        };

        self.process_reply(resp)?;

        Ok(wit_id)
    }

    /// Get witnesses for prefix and choose one randomly
    fn get_witness_for_prefix(&self, id: IdentifierPrefix) -> Result<BasicPrefix, ActorError> {
        let wit_id = self
            .get_state_for_prefix(&id)?
            .and_then(|state| {
                state
                    .witness_config
                    .witnesses
                    .choose(&mut rand::thread_rng())
                    .cloned()
            })
            .ok_or(ActorError::NoIdentState { prefix: id })?;
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

    pub fn parse_and_process_notices(&self, input_stream: &[u8]) -> Result<(), Error> {
        parse_notice_stream(input_stream)?
            .into_iter()
            .try_for_each(|notice| self.process_notice(notice))
    }

    pub async fn parse_and_process_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<PossibleResponse>, ActorError> {
        let mut responses = Vec::new();
        for query in parse_query_stream(input_stream)? {
            let result = self.process_query(query).await?;
            if let Some(response) = result {
                responses.push(response);
            }
        }
        Ok(responses)
    }

    pub fn parse_and_process_replies(&self, input_stream: &[u8]) -> Result<(), ActorError> {
        for reply in parse_reply_stream(input_stream)? {
            self.process_reply(reply)?;
        }
        Ok(())
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
        self.get_loc_scheme_for_id(id)?
            .iter()
            .map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.reply.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(ActorError::WrongReplyRoute)
                }
            })
            .collect()
    }

    pub async fn send_query_to(
        &self,
        wit_id: IdentifierPrefix,
        scheme: Scheme,
        query: SignedQuery,
    ) -> Result<PossibleResponse, ActorError> {
        let locs = self.get_loc_schemas(&wit_id)?;
        let loc = locs.into_iter().find(|loc| loc.scheme == scheme);

        let loc = match loc {
            Some(loc) => loc,
            None => return Err(ActorError::NoLocation { id: wit_id }),
        };

        let response = self.transport.send_query(loc, query).await?;

        Ok(response)
    }
}

pub struct Watcher(pub WatcherData);

impl Watcher {
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<(), ActorError> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .0
            .get_loc_scheme_for_id(&er.eid.clone())?
            .get(0)
            .ok_or(ActorError::NoLocation { id: er.eid.clone() })?
            .reply
            .data
            .data
            .clone();

        if let ReplyRoute::LocScheme(loc) = loc_scheme {
            let oobis = self
                .0
                .transport
                .request_end_role(loc, er.cid, er.role, er.eid)
                .await?;
            for m in oobis {
                match m {
                    Message::Op(op) => {
                        self.0.process_op(op).await?;
                    }
                    Message::Notice(not) => {
                        self.0.process_notice(not)?;
                    }
                }
            }
            Ok(())
        } else {
            Err(OobiError::InvalidMessageType)?
        }
    }

    pub async fn resolve_loc_scheme(&self, loc: &LocationScheme) -> Result<(), ActorError> {
        let oobis = self.0.transport.request_loc_scheme(loc.clone()).await?;
        self.0.process_ops(oobis).await?;
        Ok(())
    }
}
