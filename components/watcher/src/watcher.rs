use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use derive_more::{Display, Error, From};
use itertools::Itertools;
use keri::{
    actor::{
        parse_notice_stream, parse_query_stream, parse_reply_stream, prelude::*,
        simple_controller::PossibleResponse,
    },
    database::DbError,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event_message::signed_event_message::{Notice, Op},
    oobi::{error::OobiError, EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
    processor::{escrow::ReplyEscrow, notification::JustNotification},
    query::{
        query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
    state::IdentifierState,
};
use keri_transport::Transport;
use rand::prelude::SliceRandom;
use witness::WitnessError;

pub struct WatcherData {
    pub prefix: BasicPrefix,
    pub processor: BasicProcessor,
    event_storage: EventStorage,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    transport: Box<dyn Transport<WitnessError> + Send + Sync>,
}

impl WatcherData {
    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        priv_key: Option<String>,
        transport: Box<dyn Transport<WitnessError> + Send + Sync>,
    ) -> Result<Self, Error> {
        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or(Ok(Signer::new()))?,
        );
        let mut oobi_path = PathBuf::new();
        oobi_path.push(event_db_path);
        oobi_path.push("oobi");

        let prefix = Basic::Ed25519NT.derive(signer.public_key()); // watcher uses non transferable key
        let db = Arc::new(SledEventDatabase::new(event_db_path)?);
        let mut processor = BasicProcessor::new(db.clone(), None);
        processor.register_observer(
            Arc::new(ReplyEscrow::new(db.clone())),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::KsnOutOfOrder,
            ],
        )?;
        let storage = EventStorage::new(db.clone());
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
            SelfSigning::Ed25519Sha512.derive(signer.sign(reply.serialize()?)?),
        );
        let oobi_manager = OobiManager::new(&oobi_path);
        oobi_manager.save_oobi(&signed_reply)?;

        Ok(Self {
            prefix,
            processor,
            event_storage: storage,
            signer: signer,
            oobi_manager,
            transport,
        })
    }

    /// Get location scheme from OOBI manager and sign it.
    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Vec<SignedReply>, WatcherError> {
        Ok(match self.oobi_manager.get_loc_scheme(eid)? {
            Some(oobis_to_sign) => oobis_to_sign
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.serialize().unwrap())?;
                    Ok(SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.prefix.clone(),
                        SelfSigning::Ed25519Sha512.derive(signature),
                    ))
                })
                .collect::<Result<_, Error>>()?,
            None => return Err(WatcherError::NoLocation { id: eid.clone() }),
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

        let signature = SelfSigning::Ed25519Sha512.derive(signer.sign(&rpy.serialize()?)?);
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

    pub async fn process_op(&self, op: Op) -> Result<Option<PossibleResponse>, WatcherError> {
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
    ) -> Result<Option<PossibleResponse>, WatcherError> {
        let cid = qry.signer.clone();
        if !self.check_role(&cid)? {
            return Err(WatcherError::MissingRole {
                id: cid.clone(),
                role: Role::Watcher,
            });
        }

        match &qry.query.event.content.data.route {
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

                if escrowed_replies.len() > 0 {
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

                let signature =
                    SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
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
    async fn forward_query(&self, qry: &SignedQuery) -> Result<(), WatcherError> {
        // Create a new signed message based on the received one
        let sigs = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            self.signer.sign(qry.query.serialize()?)?,
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
    async fn query_state(&self, prefix: IdentifierPrefix) -> Result<BasicPrefix, WatcherError> {
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
            &SelfAddressing::Blake3_256,
        )?;

        // sign message by watcher
        let signature = AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            (self.signer).sign(&serde_json::to_vec(&qry).unwrap())?,
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
    fn get_witness_for_prefix(&self, id: IdentifierPrefix) -> Result<BasicPrefix, WatcherError> {
        let wit_id = self
            .get_state_for_prefix(&id)?
            .and_then(|state| {
                state
                    .witness_config
                    .witnesses
                    .choose(&mut rand::thread_rng())
                    .cloned()
            })
            .ok_or_else(|| WatcherError::NoIdentState { prefix: id })?;
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
            .map(|notice| self.process_notice(notice))
            .collect()
    }

    pub async fn parse_and_process_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<PossibleResponse>, WatcherError> {
        let mut responses = Vec::new();
        for query in parse_query_stream(input_stream)? {
            let result = self.process_query(query).await?;
            if let Some(response) = result {
                responses.push(response);
            }
        }
        Ok(responses)
    }

    pub fn parse_and_process_replies(&self, input_stream: &[u8]) -> Result<(), WatcherError> {
        for reply in parse_reply_stream(input_stream)? {
            self.process_reply(reply)?;
        }
        Ok(())
    }

    pub async fn process_ops(&self, ops: Vec<Op>) -> Result<Vec<PossibleResponse>, WatcherError> {
        let mut results = Vec::new();
        for op in ops {
            let result = self.process_op(op).await?;
            if let Some(response) = result {
                results.push(response);
            }
        }
        Ok(results)
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>, WatcherError> {
        self.get_loc_scheme_for_id(id)?
            .iter()
            .map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.reply.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(WatcherError::WrongReplyRoute)
                }
            })
            .collect()
    }

    pub async fn send_query_to(
        &self,
        wit_id: IdentifierPrefix,
        scheme: Scheme,
        query: SignedQuery,
    ) -> Result<PossibleResponse, WatcherError> {
        let locs = self.get_loc_schemas(&wit_id)?;
        let loc = locs.into_iter().find(|loc| loc.scheme == scheme);

        let loc = match loc {
            Some(loc) => loc,
            None => return Err(WatcherError::NoLocation { id: wit_id }),
        };

        let response = self.transport.send_query(loc, query).await?;

        println!("\ngot response: {:?}", response);
        Ok(response)
    }
}

pub struct Watcher(pub WatcherData);

impl Watcher {
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<(), WatcherError> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .0
            .get_loc_scheme_for_id(&er.eid.clone())?
            .get(0)
            .ok_or(WatcherError::NoLocation { id: er.eid.clone() })?
            .reply
            .event
            .content
            .data
            .clone();

        if let ReplyRoute::LocScheme(loc) = loc_scheme {
            let oobis = self
                .0
                .transport
                .request_end_role(loc, er.cid, Role::Witness, er.eid)
                .await?;
            self.0.process_ops(oobis).await?;
            Ok(())
        } else {
            Err(OobiError::InvalidMessageType)?
        }
    }

    pub async fn resolve_loc_scheme(&self, loc: &LocationScheme) -> Result<(), WatcherError> {
        let oobis = self.0.transport.request_loc_scheme(loc.clone()).await?;
        self.0.process_ops(oobis).await?;
        Ok(())
    }
}

#[derive(Debug, Display, Error, From)]
pub enum WatcherError {
    #[display(fmt = "network request failed")]
    #[from]
    TransportError(keri_transport::TransportError<WitnessError>),

    #[display(fmt = "keri error")]
    #[from]
    KeriError(keri::error::Error),

    #[display(fmt = "DB error")]
    #[from]
    DbError(keri::database::DbError),

    #[display(fmt = "OOBI error")]
    #[from]
    OobiError(keri::oobi::error::OobiError),

    #[display(fmt = "processing query failed")]
    #[from]
    QueryError(keri::actor::SignedQueryError),

    #[display(fmt = "location not found for {id:?}")]
    NoLocation { id: IdentifierPrefix },

    #[display(fmt = "wrong reply route")]
    WrongReplyRoute,

    #[display(fmt = "role {role:?} missing for {id:?}")]
    MissingRole { role: Role, id: IdentifierPrefix },

    #[display(fmt = "no identifier state for prefix {prefix:?}")]
    NoIdentState { prefix: IdentifierPrefix },
}
