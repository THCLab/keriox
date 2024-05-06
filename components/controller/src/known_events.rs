use std::path::PathBuf;
use std::sync::Arc;

use keri_core::actor::parse_event_stream;
use keri_core::database::DbError;
use keri_core::error::{self, Error};
use keri_core::event_message::signed_event_message::SignedNontransferableReceipt;
use keri_core::oobi::LocationScheme;
use keri_core::prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix};

use keri_core::processor::escrow::EscrowConfig;
use keri_core::processor::notification::JustNotification;

use keri_core::state::IdentifierState;
use keri_core::{
    actor::{self, event_generator, prelude::SelfAddressingIdentifier},
    database::{escrow::EscrowDb, SledEventDatabase},
    event::{event_data::EventData, sections::seal::Seal, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice, Op},
    },
    oobi::{OobiManager, Role, Scheme},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, PartiallyWitnessedEscrow},
        event_storage::EventStorage,
        Processor,
    },
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
};
use teliox::database::EventDatabase;
use teliox::processor::escrow::default_escrow_bus as tel_escrow_bus;
use teliox::processor::storage::TelEventStorage;
use teliox::tel::Tel;

use crate::error::ControllerError;
use crate::identifier::mechanics::MechanicsError;

#[derive(Debug, thiserror::Error)]
pub enum OobiRetrieveError {
    #[error("No oobi for {0} identifier")]
    MissingOobi(IdentifierPrefix, Option<Scheme>),
    #[error(transparent)]
    DbError(#[from] DbError),
}

pub struct KnownEvents {
    processor: BasicProcessor,
    pub storage: Arc<EventStorage>,
    pub oobi_manager: OobiManager,
    pub partially_witnessed_escrow: Arc<PartiallyWitnessedEscrow>,

    // pub tel_transport: Box<dyn GeneralTelTransport + Send + Sync>,
    pub tel: Arc<Tel>,
}

impl KnownEvents {
    pub fn new(db_path: PathBuf, escrow_config: EscrowConfig) -> Result<Self, ControllerError> {
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
            let mut path = db_path.clone();
            path.push("oobis");
            OobiManager::new(&path)
        };

        let (
            mut notification_bus,
            (
                _out_of_order_escrow,
                _partially_signed_escrow,
                partially_witnessed_escrow,
                _delegation_escrow,
            ),
        ) = default_escrow_bus(db.clone(), escrow_db, escrow_config);

        let kel_storage = Arc::new(EventStorage::new(db.clone()));

        // Initiate tel and it's escrows
        let tel_events_db = {
            let mut path = db_path.clone();
            path.push("tel");
            path.push("events");
            Arc::new(EventDatabase::new(&path)?)
        };

        let tel_escrow_db = {
            let mut path = db_path.clone();
            path.push("tel");
            path.push("escrow");
            Arc::new(EscrowDb::new(&path)?)
        };
        let tel_storage = Arc::new(TelEventStorage::new(tel_events_db));
        let (tel_bus, missing_issuer, _out_of_order, _missing_registy) = tel_escrow_bus(
            tel_storage.clone(),
            kel_storage.clone(),
            tel_escrow_db.clone(),
        )?;

        let tel = Arc::new(Tel::new(
            tel_storage.clone(),
            kel_storage.clone(),
            Some(tel_bus),
        ));

        notification_bus.register_observer(
            missing_issuer.clone(),
            vec![JustNotification::KeyEventAdded],
        );

        let controller = Self {
            processor: BasicProcessor::new(db.clone(), Some(notification_bus)),
            storage: kel_storage,
            oobi_manager,
            partially_witnessed_escrow,
            // transport,
            tel,
            // tel_transport: tel_transport,
        };

        Ok(controller)
    }

    pub fn save(&self, message: &Message) -> Result<(), MechanicsError> {
        self.process(message)?;
        Ok(())
    }

    pub fn save_oobi(&self, oobi: &SignedReply) -> Result<(), MechanicsError> {
        Ok(self.oobi_manager.process_oobi(oobi).unwrap())
    }

    pub fn current_public_keys(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .current
            .public_keys)
    }

    pub fn next_keys_hashes(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<SelfAddressingIdentifier>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .current
            .next_keys_data
            .next_key_hashes)
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

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: &Message) -> Result<Option<Vec<Message>>, Error> {
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
                Op::MailboxQuery(_) => todo!(),
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
        let messages = parse_event_stream(stream)?;
        for message in messages {
            self.process(&message)?;
        }
        Ok(())
    }

    /// Returns identifier contact information.
    pub fn get_loc_schemas(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<LocationScheme>, OobiRetrieveError> {
        let location_schemas: Vec<_> = self
            .oobi_manager
            .get_loc_scheme(id)?
            .ok_or(OobiRetrieveError::MissingOobi(id.clone(), None))?
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Some(loc_scheme)
                } else {
                    None
                }
            })
            .collect();
        if location_schemas.is_empty() {
            Err(OobiRetrieveError::MissingOobi(id.clone(), None))
        } else {
            Ok(location_schemas)
        }
    }

    pub fn find_location(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
    ) -> Result<LocationScheme, OobiRetrieveError> {
        self.get_loc_schemas(id)?
            .into_iter()
            .find(|loc| loc.scheme == scheme)
            .ok_or(OobiRetrieveError::MissingOobi(id.clone(), Some(scheme)))
    }

    pub fn find_receipt(
        &self,
        id: &IdentifierPrefix,
        sn: u64,
        digest: &SelfAddressingIdentifier,
    ) -> Result<Option<SignedNontransferableReceipt>, Error> {
        let rcts_from_db = self.storage.get_nt_receipts(id, sn, digest)?;
        Ok(rcts_from_db)
    }

    pub fn find_kel_with_receipts(&self, id: &IdentifierPrefix) -> Option<Vec<Notice>> {
        self.storage
            .get_kel_messages_with_receipts(id, None)
            .unwrap()
    }

    pub fn find_kel(&self, id: &IdentifierPrefix) -> Option<String> {
        self.storage
            .get_kel(id)
            .unwrap()
            .map(|kel| String::from_utf8(kel).unwrap())
    }

    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, MechanicsError> {
        let witnesses = witnesses
            .iter()
            .map(|wit| {
                if let IdentifierPrefix::Basic(bp) = &wit.eid {
                    Ok(bp.clone())
                } else {
                    Err(MechanicsError::WrongWitnessPrefixError)
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
        .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    /// Verifies event signature and adds it to kel.
    /// Returns new established identifier prefix.
    /// Meant to be used for identifiers with one key pair.
    /// Must call `IdentifierController::notify_witnesses` after calling this function.
    pub fn finalize_inception(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<IdentifierPrefix, MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.data.get_event_data() {
                    // TODO we assume here that provided signature matches 0th public key.
                    self.finalize_key_event(&ke, sig, 0)?;
                    Ok(ke.data.get_prefix())
                } else {
                    Err(MechanicsError::InceptionError(
                        "Wrong event type, should be inception event".into(),
                    ))
                }
            }
            _ => Err(MechanicsError::InceptionError(
                "Wrong event type, should be inception event".into(),
            )),
        }
    }

    /// Generate and return rotation event for given identifier data
    // pub fn rotate(
    //     &self,
    //     id: IdentifierPrefix,
    //     current_keys: Vec<BasicPrefix>,
    //     new_next_keys: Vec<BasicPrefix>,
    //     new_next_threshold: u64,
    //     witness_to_add: Vec<LocationScheme>,
    //     witness_to_remove: Vec<BasicPrefix>,
    //     witness_threshold: u64,
    // ) -> Result<String, ControllerError> {
    //     let witnesses_to_add = witness_to_add
    //         .iter()
    //         .map(|wit| {
    //             if let IdentifierPrefix::Basic(bp) = &wit.eid {
    //                 Ok(bp.clone())
    //             } else {
    //                 Err(ControllerError::WrongWitnessPrefixError)
    //             }
    //         })
    //         .collect::<Result<Vec<_>, _>>()?;

    //     let state = self
    //         .storage
    //         .get_state(&id)
    //         .ok_or(ControllerError::UnknownIdentifierError)?;

    //     event_generator::rotate(
    //         state,
    //         current_keys,
    //         new_next_keys,
    //         new_next_threshold,
    //         witnesses_to_add,
    //         witness_to_remove,
    //         witness_threshold,
    //     )
    //     .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    // }

    /// Generate and return interaction event for given identifier data
    // pub fn anchor(
    //     &self,
    //     id: IdentifierPrefix,
    //     payload: &[SelfAddressingIdentifier],
    // ) -> Result<String, ControllerError> {
    //     let state = self
    //         .storage
    //         .get_state(&id)
    //         .ok_or(ControllerError::UnknownIdentifierError)?;
    //     event_generator::anchor(state, payload)
    //         .map_err(|e| ControllerError::EventGenerationError(e.to_string()))
    // }

    /// Generate and return interaction event for given identifier data
    pub fn anchor_with_seal(
        &self,
        id: &IdentifierPrefix,
        payload: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, MechanicsError> {
        let state = self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?;
        event_generator::anchor_with_seal(state, payload)
            .map_err(|e| MechanicsError::EventGenerationError(e.to_string()))
    }

    pub fn get_current_witness_list(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        Ok(self
            .storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))?
            .witness_config
            .witnesses)
    }

    /// Adds signature to event and processes it.
    /// Should call `IdentifierController::notify_witnesses` after calling this function.
    pub fn finalize_key_event(
        &self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
        own_index: usize,
    ) -> Result<(), MechanicsError> {
        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        // self.processor.process_own_event(signed_message)?;
        self.process(&Message::Notice(Notice::Event(signed_message)))?;

        Ok(())
    }

    pub fn get_state_at_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
    ) -> Result<IdentifierState, MechanicsError> {
        let identifier = event_message.data.get_prefix();
        Ok(match event_message.data.get_event_data() {
            EventData::Icp(_icp) => IdentifierState::default().apply(event_message)?,
            EventData::Rot(_rot) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?
                .apply(event_message)?,
            EventData::Ixn(_ixn) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?,
            EventData::Dip(_dip) => IdentifierState::default().apply(event_message)?,
            EventData::Drt(_drt) => self
                .storage
                .get_state(&identifier)
                .ok_or(MechanicsError::UnknownIdentifierError(identifier))?
                .apply(event_message)?,
        })
    }

    pub fn find_witnesses_at_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
    ) -> Result<Vec<BasicPrefix>, MechanicsError> {
        let state = self.get_state_at_event(event_message)?;
        Ok(state.witness_config.witnesses)
    }

    pub fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(IdentifierPrefix, Vec<Message>), MechanicsError> {
        let mut messages_to_send = vec![];
        let (dest_prefix, role) = match &event.data.data {
            ReplyRoute::EndRoleAdd(role) => (role.eid.clone(), role.role.clone()),
            ReplyRoute::EndRoleCut(role) => (role.eid.clone(), role.role.clone()),
            _ => return Err(MechanicsError::EventFormatError),
        };
        let signed_reply = match signer_prefix {
            IdentifierPrefix::Basic(bp) => Message::Op(Op::Reply(SignedReply::new_nontrans(
                event,
                bp.clone(),
                sig[0].clone(),
            ))),
            _ => {
                let sigs = sig
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| IndexedSignature::new_both_same(sig, i as u16))
                    .collect();

                let signed_rpy = Message::Op(Op::Reply(SignedReply::new_trans(
                    event,
                    self.storage
                        .get_last_establishment_event_seal(signer_prefix)
                        .ok_or(MechanicsError::UnknownIdentifierError(
                            signer_prefix.clone(),
                        ))?,
                    sigs,
                )));
                if Role::Messagebox != role {
                    let kel = self
                        .storage
                        .get_kel_messages_with_receipts(signer_prefix, None)?
                        .ok_or(MechanicsError::UnknownIdentifierError(
                            signer_prefix.clone(),
                        ))?;

                    for ev in kel {
                        messages_to_send.push(Message::Notice(ev));
                    }
                };
                signed_rpy
            }
        };

        self.process(&signed_reply)?;

        messages_to_send.push(signed_reply.clone());

        Ok((dest_prefix, messages_to_send))
    }

    pub fn get_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState, MechanicsError> {
        self.storage
            .get_state(id)
            .ok_or(MechanicsError::UnknownIdentifierError(id.clone()))
    }
}
