use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
};
pub mod signing;
pub mod tel;

use keri_core::{
    actor::{
        event_generator,
        prelude::{HashFunctionCode, Message, SelfAddressingIdentifier, SerializationFormats},
        simple_controller::PossibleResponse,
        MaterialPath,
    },
    event::{
        event_data::EventData,
        sections::{
            seal::{EventSeal, Seal},
            threshold::SignatureThreshold,
        },
        KeyEvent,
    },
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signature::{Nontransferable, Signature, SignerData},
        signed_event_message::{Notice, Op, SignedEventMessage, SignedNontransferableReceipt},
    },
    mailbox::{
        exchange::{Exchange, ExchangeMessage, ForwardTopic, FwdArgs, SignedExchange},
        MailboxResponse,
    },
    oobi::{LocationScheme, Role, Scheme},
    prefix::{BasicPrefix, CesrPrimitive, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::{
        mailbox::{QueryArgsMbx, QueryTopics},
        query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery},
        reply_event::ReplyRoute,
    },
    state::IdentifierState,
};
pub use teliox::query::{SignedTelQuery, TelQueryEvent};

use super::mailbox_updating::ActionRequired;
use crate::{error::ControllerError, known_events::KnownEvents, mailbox_updating::MailboxReminder};

pub enum Query {
    Kel(QueryEvent),
    Tel(TelQueryEvent),
}

pub struct IdentifierController {
    pub id: IdentifierPrefix,
    pub source: Arc<KnownEvents>,
    pub registry_id: Option<IdentifierPrefix>,
    pub to_notify: Vec<SignedEventMessage>,
    pub state: IdentifierState,

    pub(crate) last_asked_index: Arc<Mutex<HashMap<IdentifierPrefix, MailboxReminder>>>,
    pub(crate) last_asked_groups_index: Arc<Mutex<HashMap<IdentifierPrefix, MailboxReminder>>>,
    /// Set of already broadcasted receipts.
    /// Each element contains:
    /// - event digest which uniqually identifies event.
    /// - ID of witness who signed the event which uniquely identifies a receipt.
    /// - ID of witness to which we sent this receipt.
    pub(crate) broadcasted_rcts: HashSet<(SelfAddressingIdentifier, BasicPrefix, IdentifierPrefix)>,
}

impl IdentifierController {
    pub fn new(
        id: IdentifierPrefix,
        kel: Arc<KnownEvents>,
        registry_id: Option<IdentifierPrefix>,
    ) -> Self {
        let events_to_notice: Vec<_> = kel
            .partially_witnessed_escrow
            .get_partially_witnessed_events()
            .iter()
            .filter(|ev| ev.event_message.data.prefix == id)
            .cloned()
            .collect();
        // Save state that is not fully witnessed
        let state = if let Ok(state) = kel.get_state(&id) {
            state
        } else {
            let not_accepted_incept = events_to_notice.iter().find_map(|ev| {
                if let EventData::Icp(_icp) = &ev.event_message.data.event_data {
                    Some(ev.event_message.clone())
                } else {
                    None
                }
            });
            IdentifierState::default()
                .apply(&not_accepted_incept.unwrap())
                .unwrap()
        };

        Self {
            registry_id,
            id,
            source: kel,
            state,
            last_asked_index: Arc::new(Mutex::new(HashMap::new())),
            last_asked_groups_index: Arc::new(Mutex::new(HashMap::new())),
            broadcasted_rcts: HashSet::new(),
            to_notify: events_to_notice,
        }
    }

    fn last_asked_index(&self, id: &IdentifierPrefix) -> Result<MailboxReminder, ControllerError> {
        Ok(self
            .last_asked_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        Ok(self
            .last_asked_groups_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    fn update_last_asked_index(
        &self,
        id: IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let mut indexes = self
            .last_asked_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?;
        let reminder = indexes.entry(id).or_default();
        reminder.delegate += res.delegate.len();
        reminder.multisig += res.multisig.len();
        reminder.receipt += res.receipt.len();
        Ok(())
    }

    fn update_last_asked_group_index(
        &self,
        id: IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let mut indexes = self
            .last_asked_groups_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?;
        let reminder = indexes.entry(id).or_default();
        reminder.delegate += res.delegate.len();
        reminder.multisig += res.multisig.len();
        reminder.receipt += res.receipt.len();
        Ok(())
    }

    pub fn get_kel(&self) -> Result<String, ControllerError> {
        String::from_utf8(
            self.source
                .storage
                .get_kel(&self.id)?
                .ok_or(ControllerError::UnknownIdentifierError)?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    pub fn get_last_establishment_event_seal(&self) -> Result<EventSeal, ControllerError> {
        self.source
            .storage
            .get_last_establishment_event_seal(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)
    }

    pub async fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        new_nest_threshold: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.source
            .rotate(
                self.id.clone(),
                current_keys,
                new_next_keys,
                new_nest_threshold,
                witness_to_add,
                witness_to_remove,
                witness_threshold,
            )
            .await
    }

    pub fn anchor(&self, payload: &[SelfAddressingIdentifier]) -> Result<String, ControllerError> {
        self.source.anchor(self.id.clone(), payload)
    }

    /// Generates delegating event (ixn) and exchange event that contains
    /// delegated event which will be send to delegate after ixn finalization.
    pub fn delegate(
        &self,
        delegated_event: &KeriEvent<KeyEvent>,
    ) -> Result<(KeriEvent<KeyEvent>, ExchangeMessage), ControllerError> {
        let delegate = delegated_event.data.get_prefix();
        let delegated_seal = {
            let event_digest = delegated_event.digest()?;
            let sn = delegated_event.data.get_sn();
            Seal::Event(EventSeal {
                prefix: delegate.clone(),
                sn,
                event_digest,
            })
        };
        let delegating_event = self.source.anchor_with_seal(&self.id, &[delegated_seal])?;
        let exn_message = Exchange::Fwd {
            args: FwdArgs {
                recipient_id: delegate,
                topic: ForwardTopic::Delegate,
            },
            to_forward: delegating_event.clone(),
        }
        .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;
        Ok((delegating_event, exn_message))
    }

    pub fn anchor_with_seal(
        &self,
        seal_list: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, ControllerError> {
        self.source.anchor_with_seal(&self.id, seal_list)
    }

    pub fn anchor_group(
        &self,
        group_id: &IdentifierPrefix,
        seal_list: &[Seal],
    ) -> Result<KeriEvent<KeyEvent>, ControllerError> {
        self.source.anchor_with_seal(group_id, seal_list)
    }

    /// Generates reply event with `end_role_add` route.
    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, ControllerError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, true)?
                .encode()?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    /// Generates reply event with `end_role_cut` route.
    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, ControllerError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, false)?
                .encode()?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    /// Generates reply event with `end_role_add` route and messagebox as a role..
    pub fn add_messagebox(
        &self,
        message_box_id: IdentifierPrefix,
    ) -> Result<String, ControllerError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &message_box_id, Role::Messagebox, true)?
                .encode()?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    /// Checks signatures and updates database.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function if event is a key event.
    pub async fn finalize_event(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), ControllerError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| ControllerError::EventFormatError)?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                // Provide kel for new witnesses
                // TODO  should add to notify_witness instead of sending directly?
                match &ke.data.event_data {
                    EventData::Rot(rot) | EventData::Drt(rot) => {
                        let own_kel = self
                            .source
                            .storage
                            .get_kel_messages_with_receipts(&self.id, None)?
                            .unwrap();
                        for witness in &rot.witness_config.graft {
                            let witness_id = IdentifierPrefix::Basic(witness.clone());
                            for msg in &own_kel {
                                self.source
                                    .send_message_to(
                                        &witness_id,
                                        Scheme::Http,
                                        Message::Notice(msg.clone()),
                                    )
                                    .await?;
                            }
                        }
                    }
                    _ => (),
                };

                let index = self.get_index(&ke.data).unwrap();
                self.source.finalize_key_event(&ke, &sig, index).unwrap();
                let signature = IndexedSignature::new_both_same(sig.clone(), index as u16);

                let st = self.state.clone().apply(&ke)?;
                self.state = st;

                let signed_message = ke.sign(vec![signature], None, None);
                self.to_notify.push(signed_message);

                Ok(())
            }
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => Ok(self
                    .source
                    .finalize_add_role(&self.id, rpy, vec![sig])
                    .await?),
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err(ControllerError::WrongEventTypeError),
            },
            EventType::Qry(_) => todo!(),
            EventType::Receipt(_) => todo!(),
            EventType::Exn(_) => todo!(),
        }
    }

    /// Init group identifier
    ///
    /// Returns serialized group icp and list of exchange messages to sign.
    /// Exchanges are meant to be send to witness and forwarded to group
    /// participants.
    /// If `delegator` parameter is provided, it will generate delegated
    /// inception and append delegation request to exchange messages.
    pub fn incept_group(
        &self,
        participants: Vec<IdentifierPrefix>,
        signature_threshold: u64,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<IdentifierPrefix>,
    ) -> Result<(String, Vec<String>), ControllerError> {
        let key_config = self
            .source
            .storage
            .get_state(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)?
            .current;

        let mut pks = key_config.public_keys;
        let mut npks = key_config.next_keys_data.next_key_hashes;
        for participant in &participants {
            let state = self
                .source
                .storage
                .get_state(participant)?
                .ok_or(ControllerError::UnknownIdentifierError)?;
            pks.append(&mut state.clone().current.public_keys);
            npks.append(&mut state.clone().current.next_keys_data.next_key_hashes);
        }

        let icp = event_generator::incept_with_next_hashes(
            pks,
            &SignatureThreshold::Simple(signature_threshold),
            npks,
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
            delegator.as_ref(),
        )?;

        let serialized_icp = String::from_utf8(icp.encode()?)
            .map_err(|e| ControllerError::EventGenerationError(e.to_string()))?;

        let mut exchanges = participants
            .iter()
            .map(|id| -> Result<_, _> {
                let exn = event_generator::exchange(id, &icp, ForwardTopic::Multisig)?.encode()?;
                String::from_utf8(exn).map_err(|_e| ControllerError::EventFormatError)
            })
            .collect::<Result<Vec<String>, ControllerError>>()?;

        if let Some(delegator) = delegator {
            let delegation_request = String::from_utf8(
                event_generator::exchange(&delegator, &icp, ForwardTopic::Delegate)?.encode()?,
            )
            .map_err(|_e| ControllerError::EventFormatError)?;
            exchanges.push(delegation_request);
        }

        Ok((serialized_icp, exchanges))
    }

    pub async fn finalize_exchange(
        &self,
        exchange: &[u8],
        exn_signature: SelfSigningPrefix,
        data_signature: IndexedSignature,
    ) -> Result<(), ControllerError> {
        // Join exn messages with their signatures and send it to witness.
        let material_path = MaterialPath::to_path("-a".into());
        // let attached_sig = sigs;
        let parsed_exn =
            parse_event_type(exchange).map_err(|_e| ControllerError::EventFormatError)?;
        if let EventType::Exn(exn) = parsed_exn {
            let Exchange::Fwd {
                args: _,
                to_forward,
            } = exn.data.data.clone();

            let sigs: Vec<_> = if let Some(receipts) = self.source.storage.get_nt_receipts(
                &to_forward.data.get_prefix(),
                to_forward.data.get_sn(),
                &to_forward.digest()?,
            )? {
                receipts
                    .signatures
                    .iter()
                    .map(|c| Signature::NonTransferable(c.clone()))
                    .chain([Signature::Transferable(
                        SignerData::JustSignatures,
                        vec![data_signature],
                    )])
                    .collect::<Vec<_>>()
            } else {
                vec![Signature::Transferable(
                    SignerData::JustSignatures,
                    vec![data_signature],
                )]
            };

            let signature = vec![Signature::Transferable(
                SignerData::LastEstablishment(self.id.clone()),
                vec![IndexedSignature::new_both_same(
                    exn_signature,
                    // TODO
                    0,
                )],
            )];
            let signer_exn = Message::Op(Op::Exchange(SignedExchange {
                exchange_message: exn,
                signature,
                data_signature: (material_path.clone(), sigs.clone()),
            }));
            let wits = self
                .source
                .get_state_at_event(&to_forward)?
                .witness_config
                .witnesses;
            // TODO for now get first witness
            if let Some(wit) = wits.first() {
                self.source
                    .send_message_to(
                        &IdentifierPrefix::Basic(wit.clone()),
                        keri_core::oobi::Scheme::Http,
                        signer_exn,
                    )
                    .await?;
            }
            Ok(())
        } else {
            Ok(())
        }
    }

    /// Finalizes group identifier.
    /// Joins event with signature and verifies them.
    /// Must call [`IdentifierController::notify_witnesses`] after calling this function
    /// to send signed exn messages to witness to be forwarded to group participants.
    pub async fn finalize_group_incept(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, SelfSigningPrefix)>,
    ) -> Result<IdentifierPrefix, ControllerError> {
        // Join icp event with signature
        let key_event =
            parse_event_type(group_event).map_err(|_e| ControllerError::EventFormatError)?;
        let ke = if let EventType::KeyEvent(icp) = key_event {
            icp
        } else {
            return Err(ControllerError::WrongEventTypeError);
        };
        let own_index = self.get_index(&ke.data)?;
        let group_prefix = ke.data.get_prefix();

        self.source.finalize_key_event(&ke, &sig, own_index)?;

        let signature = IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = ke.sign(vec![signature], None, None);
        self.to_notify.push(signed_message);

        let att_signature = IndexedSignature::new_both_same(sig, own_index as u16);

        for (exn, signature) in exchanges {
            self.finalize_exchange(&exn, signature, att_signature.clone())
                .await?;
        }
        Ok(group_prefix)
    }

    pub async fn notify_witnesses(&mut self) -> Result<usize, ControllerError> {
        let mut n = 0;
        while let Some(ev) = self.to_notify.pop() {
            // Elect the leader
            // Leader is identifier with minimal index among all participants who
            // sign event. He will send message to witness.
            let id_idx = self.get_index(&ev.event_message.data).unwrap_or_default();
            let min_sig_idx =
                ev.signatures
                    .iter()
                    .map(|at| at.index.current())
                    .min()
                    .expect("event should have at least one signature") as usize;
            if min_sig_idx == id_idx {
                let state = self.source.get_state_at_event(&ev.event_message)?;
                let witnesses = &state.witness_config.witnesses;
                self.source.publish(witnesses, &ev).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Helper function for getting the position of identifier's public key in
    /// group's current keys list.
    pub(crate) fn get_index(&self, group_event: &KeyEvent) -> Result<usize, ControllerError> {
        match &group_event.event_data {
            EventData::Icp(icp) => {
                // TODO what if group participant is a group and has more than one
                // public key?
                let own_pk = &self
                    .source
                    .storage
                    .get_state(&self.id)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .public_keys[0];
                icp.key_config
                    .public_keys
                    .iter()
                    .position(|pk| pk == own_pk)
            }
            EventData::Rot(rot) => {
                let own_npk = &self
                    .source
                    .storage
                    .get_state(&self.id)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .next_keys_data
                    .next_key_hashes[0];
                rot.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            }
            EventData::Dip(dip) => {
                // TODO what if group participant is a group and has more than one
                // public key?
                let own_pk = &self
                    .source
                    .storage
                    .get_state(&self.id)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .public_keys[0];
                dip.inception_data
                    .key_config
                    .public_keys
                    .iter()
                    .position(|pk| pk == own_pk)
            }
            EventData::Drt(drt) => {
                let own_npk = &self
                    .source
                    .storage
                    .get_state(&self.id)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .next_keys_data
                    .next_key_hashes[0];
                drt.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            }
            EventData::Ixn(_ixn) => {
                let own_pk = &self
                    .source
                    .storage
                    .get_state(&self.id)?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .public_keys[0];
                self.source
                    .storage
                    .get_state(&group_event.get_prefix())?
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .current
                    .public_keys
                    .iter()
                    .position(|pk| pk == own_pk)
            }
        }
        .ok_or(ControllerError::NotGroupParticipantError)
    }

   


    /// Generates query message of route `mbx` to query own identifier mailbox.
    pub fn query_mailbox(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        witnesses
            .iter()
            .map(|wit| -> Result<_, ControllerError> {
                let recipient = IdentifierPrefix::Basic(wit.clone());

                let reminder = if identifier == &self.id {
                    // request own mailbox
                    self.last_asked_index(&recipient)
                } else {
                    // request group mailbox
                    self.last_asked_group_index(&recipient)
                }?;

                Ok(QueryEvent::new_query(
                    QueryRoute::Mbx {
                        args: QueryArgsMbx {
                            // about who
                            i: identifier.clone(),
                            // who is asking
                            pre: self.id.clone(),
                            // who will get the query
                            src: recipient,
                            topics: QueryTopics {
                                credential: 0,
                                receipt: reminder.receipt,
                                replay: 0,
                                multisig: reminder.multisig,
                                delegate: reminder.delegate,
                                reply: 0,
                            },
                        },
                        reply_route: "".to_string(),
                    },
                    SerializationFormats::JSON,
                    HashFunctionCode::Blake3_256,
                )?)
            })
            .collect()
    }

    pub fn query_watcher(
        &self,
        seal: &EventSeal,
        watcher: IdentifierPrefix,
    ) -> Result<QueryEvent, ControllerError> {
        Ok(QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(seal.sn),
                    i: seal.prefix.clone(),
                    src: Some(watcher),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )?)
    }

    pub fn query_own_watchers(
        &self,
        about_who: &EventSeal,
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        self.source
            .get_watchers(&self.id)?
            .into_iter()
            .map(|watcher| self.query_watcher(about_who, watcher))
            .collect()
    }

    async fn mailbox_response(
        &self,
        recipient: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
        about_who: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let req = if from_who == about_who {
            // process own mailbox
            let req = self.process_own_mailbox(res)?;
            self.update_last_asked_index(recipient.clone(), res)?;
            req
        } else {
            // process group mailbox
            let group_req = self.process_group_mailbox(res, about_who).await?;
            self.update_last_asked_group_index(recipient.clone(), res)?;
            group_req
        };
        Ok(req)
    }

    /// Joins query events with their signatures, sends it to witness and
    /// process its response. If user action is needed to finalize process,
    /// returns proper notification.
    pub async fn finalize_query(
        &self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let self_id = self.id.clone();
        let mut actions = Vec::new();
        for (qry, sig) in queries {
            let (recipient, about_who, from_who) = match qry.get_route() {
                QueryRoute::Logs {
                    reply_route: _,
                    args,
                } => (args.src.clone(), Some(&args.i), Some(&self.id)),
                QueryRoute::Ksn {
                    reply_route: _,
                    args,
                } => (
                    args.src.clone(),
                    // .ok_or_else(|| {
                    //     ControllerError::QueryArgumentError(
                    //         "Missing query recipient identifier".into(),
                    //     )
                    // })?,
                    None,
                    None,
                ),
                QueryRoute::Mbx {
                    reply_route: _,
                    args,
                } => (Some(args.src.clone()), Some(&args.i), Some(&args.pre)),
            };
            let query = match &self.id {
                IdentifierPrefix::Basic(bp) => {
                    SignedKelQuery::new_nontrans(qry.clone(), bp.clone(), sig)
                }
                _ => {
                    let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                    SignedKelQuery::new_trans(qry.clone(), self_id.clone(), signatures)
                }
            };
            let res = self
                .source
                .send_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
                .await?;

            match res {
                PossibleResponse::Kel(kel) => {
                    for event in kel {
                        self.source.process(&event)?;
                    }
                }
                PossibleResponse::Mbx(mbx) => {
                    // only process if we actually asked about mailbox
                    if let (Some(from_who), Some(about_who)) =
                        (from_who.as_ref(), about_who.as_ref())
                    {
                        actions.append(
                            &mut self
                                .mailbox_response(&recipient.unwrap(), from_who, about_who, &mbx)
                                .await?,
                        );
                    }
                }
                PossibleResponse::Ksn(_) => todo!(),
            };
        }
        Ok(actions)
    }

    pub async fn finalize_tel_query(
        &self,
        issuer_id: &IdentifierPrefix,
        qry: TelQueryEvent,
        sig: SelfSigningPrefix,
    ) -> Result<(), ControllerError> {
        let query = match &self.id {
            IdentifierPrefix::Basic(bp) => {
                SignedTelQuery::new_nontrans(qry.clone(), bp.clone(), sig)
            }
            _ => {
                let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                SignedTelQuery::new_trans(qry.clone(), self.id.clone(), signatures)
            }
        };
        let witness = self.source.get_current_witness_list(issuer_id)?[0].clone();
        let location = self
            .source
            .get_loc_schemas(&IdentifierPrefix::Basic(witness))?[0]
            .clone();
        let tel_res = self
            .source
            .tel_transport
            .send_query(query, location)
            .await
            .map_err(|e| ControllerError::OtherError(e.to_string()))?;
        self.source
            .tel
            .parse_and_process_tel_stream(tel_res.as_bytes())?;

        Ok(())
    }

    /// Send new receipts obtained via [`Self::finalize_query`] to specified witnesses.
    /// Returns number of new receipts sent per witness or first error.
    pub async fn broadcast_receipts(
        &mut self,
        dest_wit_ids: &[IdentifierPrefix],
    ) -> Result<usize, ControllerError> {
        let receipts = self
            .source
            .storage
            .db
            .get_receipts_nt(&self.id)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut n = 0;

        for rct in receipts {
            let rct_digest = rct.body.receipted_event_digest.clone();
            let rct_wit_ids = self.get_wit_ids_of_rct(&rct)?;

            for dest_wit_id in dest_wit_ids {
                // Don't send receipt to witness who created it.
                // TODO: this only works if the target witness ID is a BasicPrefix.
                if let IdentifierPrefix::Basic(dest_wit_id) = dest_wit_id {
                    if rct_wit_ids.contains(dest_wit_id) {
                        continue;
                    }
                }

                // Don't send the same receipt twice.
                if rct_wit_ids.iter().all(|rct_wit_id| {
                    self.broadcasted_rcts.contains(&(
                        rct_digest.clone(),
                        rct_wit_id.clone(),
                        dest_wit_id.clone(),
                    ))
                }) {
                    continue;
                }

                self.source
                    .send_message_to(
                        dest_wit_id,
                        Scheme::Http,
                        Message::Notice(Notice::NontransferableRct(rct.clone())),
                    )
                    .await?;

                // Remember event digest and witness ID to avoid sending the same receipt twice.
                for rct_wit_id in &rct_wit_ids {
                    self.broadcasted_rcts.insert((
                        rct_digest.clone(),
                        rct_wit_id.clone(),
                        dest_wit_id.clone(),
                    ));
                }

                n += 1;
            }
        }

        Ok(n)
    }

    /// Get IDs of witnesses who signed given receipt.
    fn get_wit_ids_of_rct(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<Vec<BasicPrefix>, ControllerError> {
        let mut wit_ids = Vec::new();
        for sig in &rct.signatures {
            match sig {
                Nontransferable::Indexed(sigs) => {
                    for sig in sigs {
                        let wits = self.source.storage.get_witnesses_at_event(
                            rct.body.sn,
                            &self.id,
                            &rct.body.receipted_event_digest,
                        )?;
                        wit_ids.push(wits[sig.index.current() as usize].clone());
                    }
                }
                Nontransferable::Couplet(sigs) => {
                    for (wit_id, _sig) in sigs {
                        wit_ids.push(wit_id.clone());
                    }
                }
            }
        }
        Ok(wit_ids)
    }

    /// Splits input string into oobis to resolve and signed data, sends oobi to
    /// watchers and verify provided credentials.
    pub async fn verify_stream(&self, stream: &str) -> Result<(), ControllerError> {
        let (oobis, parsed) = self.source.parse_cesr_stream(stream)?;
        for oobi in oobis {
            self.source.send_oobi_to_watcher(&self.id, &oobi).await?;
        }
        self.source.verify_parsed(&parsed)
    }

    /// Helper function that produces transferable signature made with
    /// keys corresponding to event in kel that is specified with event_seal. It
    /// computes indexes of provided `SelfSigningIdentifier`s and build `Signature`
    /// from them.
    pub fn transferable_signature(
        &self,
        data: &[u8],
        event_seal: EventSeal,
        signatures: &[SelfSigningPrefix],
    ) -> Result<Signature, ControllerError> {
        let state = self.source.get_state(&self.id)?.current.public_keys;
        let indexed_signatures: Option<Vec<_>> = signatures
            .iter()
            .map(|sig| {
                (
                    sig,
                    (state
                        .iter()
                        .position(|bp| bp.verify(data, sig).ok().is_some())),
                )
            })
            .map(|(sig, index)| {
                index.map(|i| IndexedSignature::new_both_same(sig.clone(), i as u16))
            })
            .collect();
        let signature = Signature::Transferable(
            SignerData::EventSeal(event_seal),
            indexed_signatures.expect("Provided signatures do not match any of the keys corresponding to the provided event seal"),
        );
        Ok(signature)
    }
}
