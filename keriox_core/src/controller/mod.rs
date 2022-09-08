use std::{path::PathBuf, sync::Arc};

pub mod error;
pub mod event_generator;
pub mod identifier_controller;
#[cfg(test)]
mod test;
pub mod utils;
pub mod action_request;

use self::{
    error::ControllerError,
    utils::{OptionalConfig, Topic},
};
use crate::{
    actor,
    database::{escrow::EscrowDb, SledEventDatabase},
    event::{event_data::EventData, sections::seal::Seal, EventMessage},
    event_message::{
        key_event_message::KeyEvent,
        signed_event_message::{Message, Notice, Op, SignedEventMessage},
        Digestible,
    },
    event_parsing::{
        message::key_event_message,
        EventType, SignedEventData,
    },
    oobi::{LocationScheme, OobiManager, Role, Scheme},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, PartiallyWitnessedEscrow},
        event_storage::EventStorage,
        Processor,
    },
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};

pub struct Controller {
    processor: BasicProcessor,
    pub storage: EventStorage,
    oobi_manager: OobiManager,
    partially_witnessed_escrow: Arc<PartiallyWitnessedEscrow>,
}
impl Controller {
    pub fn new(configs: Option<OptionalConfig>) -> Result<Self, ControllerError> {
        let (db_dir_path, initial_oobis) = match configs {
            Some(OptionalConfig {
                db_path,
                initial_oobis,
            }) => (db_path.unwrap_or(PathBuf::from("./db")), initial_oobis),
            None => (PathBuf::from("./db"), None),
        };

        let mut events_db = db_dir_path.clone();
        events_db.push("events");
        let mut oobis_db = db_dir_path.clone();
        oobis_db.push("oobis");
        let mut escrow_db = db_dir_path.clone();
        escrow_db.push("escrow");

        let db = Arc::new(SledEventDatabase::new(events_db.as_path())?);
        let escrow_db = Arc::new(EscrowDb::new(escrow_db.as_path())?);
        let (notification_bus, (_, _partially_signed_escrow, partially_witnessed_escrow, _)) =
            default_escrow_bus(db.clone(), escrow_db);

        let controller = Self {
            processor: BasicProcessor::new(db.clone(), Some(notification_bus)),
            storage: EventStorage::new(db),
            oobi_manager: OobiManager::new(&oobis_db),
            partially_witnessed_escrow,
        };

        if let Some(initial_oobis) = initial_oobis {
            controller.setup_witnesses(&initial_oobis)?;
        }

        Ok(controller)
    }

    fn setup_witnesses(&self, oobis: &[LocationScheme]) -> Result<(), ControllerError> {
        oobis
            .iter()
            .try_for_each(|lc| self.resolve_loc_schema(lc))?;
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), ControllerError> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::blocking::get(url)
            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?
            .text()
            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?;
        self.process_stream(oobis.as_bytes())
    }

    fn get_watchers(
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
    pub fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        end_role_json: &str,
    ) -> Result<(), ControllerError> {
        for watcher in self.get_watchers(id)?.iter() {
            self.send_to(
                &watcher,
                Scheme::Http,
                Topic::Oobi(end_role_json.as_bytes().to_vec()),
            )?;
        }

        Ok(())
    }

    /// Query watcher (TODO randomly chosen, for now asks first found watcher)
    /// about id kel and updates local kel.
    pub fn query(&self, id: &IdentifierPrefix, query_id: &str) -> Result<(), ControllerError> {
        let watchers = self.get_watchers(id)?;
        // TODO choose random watcher id?
        // TODO we assume that we get the answer immediately which is not always true
        let to_parse = self.send_to(&watchers[0], Scheme::Http, Topic::Query(query_id.into()))?;
        self.process_stream(to_parse.as_bytes())
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
            .ok_or_else(|| ControllerError::UnknownIdentifierError)?
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

    fn send_to(
        &self,
        id: &IdentifierPrefix,
        schema: Scheme,
        topic: Topic,
    ) -> Result<String, ControllerError> {
        let addresses = self.get_loc_schemas(id)?;
        match addresses
            .iter()
            // TODO It uses first found address that match schema
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => match schema {
                Scheme::Http => {
                    let client = reqwest::blocking::Client::new();
                    let response = match topic {
                        Topic::Oobi(oobi_json) => client
                            .post(format!("{}resolve", address))
                            .body(oobi_json)
                            .send()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?
                            .text()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?,
                        Topic::Query(id) => client
                            .get(format!("{}query/{}", address, id))
                            .send()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?
                            .text()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?,
                        Topic::Process(to_process) => client
                            .post(format!("{}process", address))
                            .body(to_process)
                            .send()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?
                            .text()
                            .map_err(|e| ControllerError::CommunicationError(e.to_string()))?,
                    };

                    Ok(response)
                }
                Scheme::Tcp => {
                    todo!()
                }
            },
            _ => Err(ControllerError::CommunicationError(format!(
                "No address for scheme {:?}",
                schema
            ))),
        }
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    fn publish(
        &self,
        witness_prefixes: &[BasicPrefix],
        message: &SignedEventMessage,
    ) -> Result<(), ControllerError> {
        let msg = SignedEventData::from(message).to_cesr()?;
        let collected_receipts = witness_prefixes
            .iter()
            .map(|prefix| {
                self.send_to(
                    &IdentifierPrefix::Basic(prefix.clone()),
                    Scheme::Http,
                    Topic::Process(msg.clone()),
                )
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?
            .join("");
        // process collected receipts
        self.process_stream(collected_receipts.as_bytes())?;

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let (prefix, sn, digest) = (
            message.event_message.event.get_prefix(),
            message.event_message.event.get_sn(),
            message.event_message.event.get_digest(),
        );
        let rcts_from_db = self.storage.get_nt_receipts(&prefix, sn, &digest)?;

        match rcts_from_db {
            Some(receipts) => {
                let serialized_receipts = SignedEventData::from(receipts).to_cesr()?;
                // send receipts to all witnesses
                witness_prefixes
                    .iter()
                    .try_for_each(|prefix| -> Result<_, ControllerError> {
                        self.send_to(
                            &IdentifierPrefix::Basic(prefix.clone()),
                            Scheme::Http,
                            Topic::Process(serialized_receipts.clone()),
                        )?;
                        Ok(())
                    })?;
            }
            None => (),
        };

        Ok(())
    }

    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.setup_witnesses(&witnesses)?;
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
    }

    /// Verify event signature, add it to kel, and publish it to witnesses.
    /// Returns new established identifier prefix. Ment to be used for
    /// identifiers with one keypair.
    pub fn finalize_inception(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<IdentifierPrefix, ControllerError> {
        let (_, parsed_event) =
            key_event_message(event).map_err(|_e| ControllerError::EventParseError)?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.event.get_event_data() {
                    self.finalize_key_event(&ke, sig, 0)?;
                    Ok(ke.event.get_prefix())
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
    pub fn rotate(
        &self,
        id: IdentifierPrefix,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.setup_witnesses(&witness_to_add)?;
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
    }

    /// Generate and return interaction event for given identifier data
    pub fn anchor(
        &self,
        id: IdentifierPrefix,
        payload: &[SelfAddressingPrefix],
    ) -> Result<String, ControllerError> {
        let state = self
            .storage
            .get_state(&id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        event_generator::anchor(state, payload)
    }

    /// Generate and return interaction event for given identifier data
    pub fn anchor_with_seal(
        &self,
        id: IdentifierPrefix,
        payload: &[Seal],
    ) -> Result<EventMessage<KeyEvent>, ControllerError> {
        let state = self
            .storage
            .get_state(&id)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        event_generator::anchor_with_seal(state, payload)
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

    fn finalize_key_event(
        &self,
        event: &EventMessage<KeyEvent>,
        sig: &SelfSigningPrefix,
        own_index: usize,
    ) -> Result<(), ControllerError> {
        let signature = AttachedSignaturePrefix {
            index: own_index as u16,
            signature: sig.clone(),
        };

        let signed_message = event.sign(vec![signature], None, None);
        self.process(&Message::Notice(Notice::Event(signed_message.clone())))?;

        let id = event.event.get_prefix();
        let fully_signed_event = self.partially_witnessed_escrow.get_event_by_sn_and_digest(
            event.event.get_sn(),
            &id,
            &event.get_digest(),
        );

        // Elect the leader
        // Leader is identifier with minimal index among all participants who
        // sign event. He will send message to witness.
        let to_publish = fully_signed_event.and_then(|ev| {
            ev.signatures
                .iter()
                .map(|at| at.index)
                .min()
                .and_then(|index| {
                    if index as usize == own_index {
                        Some(ev)
                    } else {
                        // Not a leader
                        None
                    }
                })
        });

        if let Some(to_pub) = to_publish {
            let witnesses =
                self.get_current_witness_list(&to_pub.event_message.event.get_prefix())?;
            self.publish(&witnesses, &to_pub)?;
        };
        Ok(())
    }

    fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), ControllerError> {
        let sigs = sig
            .into_iter()
            .enumerate()
            .map(|(i, sig)| AttachedSignaturePrefix {
                index: i as u16,
                signature: sig,
            })
            .collect();

        let dest_prefix = match &event.event.content.data {
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
        let mut kel = self
            .storage
            .get_kel(signer_prefix)?
            .ok_or(ControllerError::UnknownIdentifierError)?;
        kel.extend(signed_rpy.to_cesr()?);

        self.send_to(&dest_prefix, Scheme::Http, Topic::Process(kel))?;
        self.process(&signed_rpy)?;
        Ok(())
    }
}
