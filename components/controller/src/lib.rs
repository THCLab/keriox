use std::{path::PathBuf, sync::Arc};

pub mod error;
pub mod identifier_controller;
pub mod mailbox_updating;
mod test;

use keri::{
    actor::{
        self, event_generator, prelude::SelfAddressingIdentifier,
        simple_controller::PossibleResponse,
    },
    database::{escrow::EscrowDb, SledEventDatabase},
    event::{event_data::EventData, sections::seal::Seal, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice, Op, SignedEventMessage},
    },
    oobi::{LocationScheme, Oobi, OobiManager, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, PartiallyWitnessedEscrow},
        event_storage::EventStorage,
        Processor,
    },
    query::{
        query_event::SignedQuery,
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    },
    transport::{default::DefaultTransport, Transport},
};

use self::error::ControllerError;

pub struct Controller {
    processor: BasicProcessor,
    pub storage: EventStorage,
    oobi_manager: OobiManager,
    partially_witnessed_escrow: Arc<PartiallyWitnessedEscrow>,
    transport: Box<dyn Transport + Send + Sync>,
}

pub struct ControllerConfig {
    pub db_path: PathBuf,
    pub initial_oobis: Vec<LocationScheme>,
    pub escrow_config: EscrowConfig,
    pub transport: Box<dyn Transport + Send + Sync>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("db"),
            initial_oobis: vec![],
            escrow_config: EscrowConfig::default(),
            transport: Box::new(DefaultTransport::new()),
        }
    }
}

impl Controller {
    pub fn new(config: ControllerConfig) -> Result<Self, ControllerError> {
        let ControllerConfig {
            db_path,
            initial_oobis,
            escrow_config,
            transport,
        } = config;

        let db = {
            let mut path = db_path.clone();
            path.push("events");
            Arc::new(SledEventDatabase::new(&path)?)
        };

        let escrow_db = {
            let mut path = db_path.clone();
            path.push("escrow");
            Arc::new(EscrowDb::new(&path)?)
        };

        let oobi_manager = {
            let mut path = db_path;
            path.push("oobis");
            OobiManager::new(&path)
        };

        let (
            notification_bus,
            (
                _out_of_order_escrow,
                _partially_signed_escrow,
                partially_witnessed_escrow,
                _delegation_escrow,
            ),
        ) = default_escrow_bus(db.clone(), escrow_db, escrow_config);

        let controller = Self {
            processor: BasicProcessor::new(db.clone(), Some(notification_bus)),
            storage: EventStorage::new(db),
            oobi_manager,
            partially_witnessed_escrow,
            transport,
        };

        if !initial_oobis.is_empty() {
            async_std::task::block_on(controller.setup_witnesses(&initial_oobis))?;
        }

        Ok(controller)
    }

    async fn setup_witnesses(&self, oobis: &[LocationScheme]) -> Result<(), ControllerError> {
        for lc in oobis {
            self.resolve_loc_schema(lc).await?;
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), ControllerError> {
        let oobis = self.transport.request_loc_scheme(lc.clone()).await?;
        for oobi in oobis {
            self.process(&Message::Op(oobi))?;
        }
        Ok(())
    }

    pub fn get_watchers(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<IdentifierPrefix>, ControllerError> {
        Ok(self
            .oobi_manager
            .get_end_role(id, Role::Watcher)?
            .into_iter()
            .filter_map(|r| {
                if let ReplyRoute::EndRoleAdd(adds) = r.reply.get_route() {
                    Some(adds.eid)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>())
    }

    /// Sends identifier's endpoint information to identifiers's watchers.
    // TODO use stream instead of json
    pub async fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        oobi_json: &str,
    ) -> Result<(), ControllerError> {
        let oobi: Oobi = serde_json::from_str(oobi_json).unwrap();
        for watcher in self.get_watchers(id)?.iter() {
            self.send_oobi_to(watcher, Scheme::Http, oobi.clone())
                .await?;
        }

        Ok(())
    }

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: &Message) -> Result<Option<Vec<Message>>, ControllerError> {
        let response = match msg.clone() {
            Message::Op(op) => match op {
                Op::Reply(rpy) => {
                    actor::process_reply(rpy, &self.oobi_manager, &self.processor, &self.storage)?;
                    None
                }
                Op::Query(_) => {
                    // TODO: Should controller respond to queries?
                    None
                }
                Op::Exchange(_) => todo!(),
            },
            Message::Notice(notice) => {
                self.processor.process_notice(&notice)?;
                None
            }
        };

        Ok(response)
    }

    /// Parse and process events stream
    pub fn process_stream(&self, stream: &[u8]) -> Result<(), ControllerError> {
        let messages = crate::actor::parse_event_stream(stream)?;
        for message in messages {
            self.process(&message)?;
        }
        Ok(())
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<LocationScheme>, ControllerError> {
        Ok(self
            .oobi_manager
            .get_loc_scheme(id)?
            .ok_or(ControllerError::UnknownIdentifierError)?
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(ControllerError::WrongEventTypeError)
                }
                .ok()
            })
            .collect())
    }

    async fn send_message_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        msg: Message,
    ) -> Result<(), ControllerError> {
        let loc = self
            .get_loc_schemas(id)?
            .into_iter()
            .find(|loc| loc.scheme == scheme);
        let loc = match loc {
            Some(loc) => loc,
            None => {
                return Err(ControllerError::NoLocationScheme {
                    id: id.clone(),
                    scheme,
                });
            }
        };
        self.transport.send_message(loc, msg).await?;
        Ok(())
    }

    async fn send_query_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        query: SignedQuery,
    ) -> Result<PossibleResponse, ControllerError> {
        let loc = self
            .get_loc_schemas(id)?
            .into_iter()
            .find(|loc| loc.scheme == scheme);
        let loc = match loc {
            Some(loc) => loc,
            None => {
                return Err(ControllerError::NoLocationScheme {
                    id: id.clone(),
                    scheme,
                });
            }
        };
        Ok(self.transport.send_query(loc, query).await?)
    }

    async fn send_oobi_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        oobi: Oobi,
    ) -> Result<(), ControllerError> {
        let loc = self
            .get_loc_schemas(id)?
            .into_iter()
            .find(|loc| loc.scheme == scheme)
            .ok_or(ControllerError::NoLocationScheme {
                id: id.clone(),
                scheme,
            })?;

        self.transport.resolve_oobi(loc, oobi).await?;
        Ok(())
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    async fn publish(
        &self,
        witness_prefixes: &[BasicPrefix],
        message: &SignedEventMessage,
    ) -> Result<(), ControllerError> {
        for id in witness_prefixes {
            self.send_message_to(
                &IdentifierPrefix::Basic(id.clone()),
                Scheme::Http,
                Message::Notice(Notice::Event(message.clone())),
            )
            .await?;
            // process collected receipts
            // send query message for receipt mailbox
            // TODO: get receipts from mailbox
            // for receipt in receipts {
            //     self.process(&receipt)?;
            // }
        }

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let (prefix, sn, digest) = (
            message.event_message.data.get_prefix(),
            message.event_message.data.get_sn(),
            message.event_message.digest(),
        );
        let rcts_from_db = self.storage.get_nt_receipts(&prefix, sn, &digest?)?;

        if let Some(receipt) = rcts_from_db {
            // send receipts to all witnesses
            for prefix in witness_prefixes {
                self.send_message_to(
                    &IdentifierPrefix::Basic(prefix.clone()),
                    Scheme::Http,
                    Message::Notice(Notice::NontransferableRct(receipt.clone())),
                )
                .await?;
            }
        };

        Ok(())
    }

    pub async fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.setup_witnesses(&witnesses).await?;
        let witnesses = witnesses
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(ControllerError::WrongWitnessPrefixError)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        event_generator::incept(
            public_keys,
            next_pub_keys,
            witnesses,
            witness_threshold,
            None,
        )
        .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    }

    /// Verifies event signature and adds it to kel.
    /// Returns new established identifier prefix.
    /// Meant to be used for identifiers with one key pair.
    /// Must call `IdentifierController::notify_witnesses` after calling this function.
    pub async fn finalize_inception(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<IdentifierPrefix, ControllerError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| ControllerError::EventParseError)?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.data.get_event_data() {
                    self.finalize_key_event(&ke, sig, 0)?;
                    Ok(ke.data.get_prefix())
                } else {
                    Err(ControllerError::InceptionError(
                        "Wrong event type, should be inception event".into(),
                    ))
                }
            }
            _ => Err(ControllerError::InceptionError(
                "Wrong event type, should be inception event".into(),
            )),
        }
    }

    /// Generate and return rotation event for given identifier data
    pub async fn rotate(
        &self,
        id: IdentifierPrefix,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.setup_witnesses(&witness_to_add).await?;
        let witnesses_to_add = witness_to_add
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(ControllerError::WrongWitnessPrefixError)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let state = self
            .storage
            .get_state(&id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;

        event_generator::rotate(
            state,
            current_keys,
            new_next_keys,
            witnesses_to_add,
            witness_to_remove,
            witness_threshold,
        )
        .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    }

    /// Generate and return interaction event for given identifier data
    pub fn anchor(
        &self,
        id: IdentifierPrefix,
        payload: &[SelfAddressingIdentifier],
    ) -> Result<String, ControllerError> {
        let state = self
            .storage
            .get_state(&id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        event_generator::anchor(state, payload)
            .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    }

    /// Generate and return interaction event for given identifier data
    pub fn anchor_with_seal(
        &self,
        id: &IdentifierPrefix,
        payload: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, ControllerError> {
        let state = self
            .storage
            .get_state(id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        event_generator::anchor_with_seal(state, payload)
            .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    }

    fn get_current_witness_list(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, ControllerError> {
        Ok(self
            .storage
            .get_state(id)?
            .ok_or(ControllerError::UnknownIdentifierError)?
            .witness_config
            .witnesses)
    }

    /// Adds signature to event and processes it.
    /// Should call `IdentifierController::notify_witnesses` after calling this function.
    fn finalize_key_event(
        &self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
        own_index: usize,
    ) -> Result<(), ControllerError> {
        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        self.process(&Message::Notice(Notice::Event(signed_message)))?;

        Ok(())
    }

    pub fn get_witnesses_at_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
    ) -> Result<Vec<BasicPrefix>, ControllerError> {
        let identifier = event_message.data.get_prefix();
        Ok(match event_message.data.get_event_data() {
            EventData::Icp(icp) => icp.witness_config.initial_witnesses,
            EventData::Rot(_rot) => todo!(),
            EventData::Ixn(_ixn) => {
                self.storage
                    .get_state(&identifier)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .witness_config
                    .witnesses
            }
            EventData::Dip(dip) => dip.inception_data.witness_config.initial_witnesses,
            EventData::Drt(_) => todo!(),
        })
    }

    async fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), ControllerError> {
        let sigs = sig
            .into_iter()
            .enumerate()
            .map(|(i, sig)| IndexedSignature::new_both_same(sig, i as u16))
            .collect();

        let dest_prefix = match &event.data.data {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(_) => todo!(),
            ReplyRoute::EndRoleAdd(role) => role.eid.clone(),
            ReplyRoute::EndRoleCut(role) => role.eid.clone(),
        };
        let signed_rpy = Message::Op(Op::Reply(SignedReply::new_trans(
            event,
            self.storage
                .get_last_establishment_event_seal(signer_prefix)?
                .ok_or(ControllerError::UnknownIdentifierError)?,
            sigs,
        )));
        let kel = self
            .storage
            .get_kel_messages_with_receipts(signer_prefix)?
            .ok_or(ControllerError::UnknownIdentifierError)?;

        // TODO: send in one request
        for ev in kel {
            self.send_message_to(&dest_prefix, Scheme::Http, Message::Notice(ev))
                .await?;
        }
        self.send_message_to(&dest_prefix, Scheme::Http, signed_rpy.clone())
            .await?;

        self.process(&signed_rpy)?;
        Ok(())
    }
}
