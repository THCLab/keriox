use std::sync::Arc;

use keri::{
    actor::{
        event_generator,
        prelude::Message,
        simple_controller::{parse_response, PossibleResponse},
    },
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    event::{
        event_data::EventData,
        sections::{
            seal::{EventSeal, Seal},
            threshold::SignatureThreshold,
        },
        EventMessage, SerializationFormats,
    },
    event_message::{
        exchange::{Exchange, ExchangeMessage, ForwardTopic, FwdArgs, SignedExchange},
        key_event_message::KeyEvent,
        signature::{Nontransferable, Signature, SignerData},
        signed_event_message::{Op, SignedEventMessage},
    },
    event_parsing::{
        message::{event_message, exchange_message, key_event_message},
        path::MaterialPath,
        EventType,
    },
    oobi::{LocationScheme, Role, Scheme},
    prefix::{
        AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix, SelfAddressingPrefix,
        SelfSigningPrefix,
    },
    query::{
        query_event::{
            MailboxResponse, QueryArgsMbx, QueryEvent, QueryRoute, QueryTopics, SignedQuery,
        },
        reply_event::ReplyRoute,
    },
};

use crate::{error::ControllerError, utils::Topic, Controller};

use super::mailbox_updating::ActionRequired;

#[derive(Default)]
pub struct MailboxReminder {
    pub receipt: usize,
    pub multisig: usize,
    pub delegate: usize,
}
impl MailboxReminder {
    pub fn update_receipt(&mut self) {
        self.receipt = self.receipt + 1;
    }
    pub fn update_multisig(&mut self) {
        self.receipt = self.multisig + 1;
    }
    pub fn update_delegate(&mut self) {
        self.receipt = self.delegate + 1;
    }
}

pub struct IdentifierController {
    pub id: IdentifierPrefix,
    pub groups: Vec<IdentifierPrefix>,
    pub source: Arc<Controller>,
    last_asked_index: MailboxReminder,
    last_asked_groups_index: MailboxReminder,
}

impl IdentifierController {
    pub fn new(id: IdentifierPrefix, kel: Arc<Controller>) -> Self {
        Self {
            id,
            source: kel,
            groups: vec![],
            last_asked_index: MailboxReminder::default(),
            last_asked_groups_index: MailboxReminder::default(),
        }
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

    pub fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.source.rotate(
            self.id.clone(),
            current_keys,
            new_next_keys,
            witness_to_add,
            witness_to_remove,
            witness_threshold,
        )
    }

    pub fn anchor(&self, payload: &[SelfAddressingPrefix]) -> Result<String, ControllerError> {
        self.source.anchor(self.id.clone(), payload)
    }

    pub fn delegate(
        &self,
        delegated_event: EventMessage<KeyEvent>,
    ) -> Result<(EventMessage<KeyEvent>, ExchangeMessage), ControllerError> {
        let delegate = delegated_event.event.get_prefix();
        let delegated_seal = {
            let event_digest = delegated_event.get_digest();
            let sn = delegated_event.event.get_sn();
            Seal::Event(EventSeal {
                prefix: delegate.clone(),
                sn,
                event_digest,
            })
        };
        let ixn = self.source.anchor_with_seal(&self.id, &[delegated_seal])?;
        let exn_message = Exchange::Fwd {
            args: FwdArgs {
                recipient_id: delegate.clone(),
                topic: ForwardTopic::Delegate,
            },
            to_forward: delegated_event.clone(),
        }
        .to_message(SerializationFormats::JSON, &SelfAddressing::Blake3_256)?;
        Ok((ixn, exn_message))
    }

    pub fn anchor_with_seal(
        &self,
        seal_list: &[Seal],
    ) -> Result<EventMessage<KeyEvent>, ControllerError> {
        self.source.anchor_with_seal(&self.id, seal_list)
    }

    pub fn anchor_group(
        &self,
        group_id: &IdentifierPrefix,
        seal_list: &[Seal],
    ) -> Result<EventMessage<KeyEvent>, ControllerError> {
        self.source.anchor_with_seal(group_id, seal_list)
    }

    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, ControllerError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, true)?
                .serialize()?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, ControllerError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, false)?
                .serialize()?,
        )
        .map_err(|_e| ControllerError::EventFormatError)
    }

    /// Check signatures, updates database and send events to watcher or
    /// witnesses.
    pub fn finalize_event(
        &self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), ControllerError> {
        let parsed_event = event_message(event)
            .map_err(|_e| ControllerError::EventParseError)?
            .1;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                let index = self.get_index(&ke.event)?;
                self.source.finalize_key_event(&ke, &sig, index)
            }
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => {
                    Ok(self.source.finalize_add_role(&self.id, rpy, vec![sig])?)
                }
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
        let key_config = self.source.storage.get_state(&self.id)?.unwrap().current;
        let (pks, npks) = participants.iter().fold(
            (
                key_config.public_keys,
                key_config.next_keys_data.next_key_hashes,
            ),
            |mut acc, id| {
                let state = self.source.storage.get_state(id).unwrap().unwrap();
                acc.0.append(&mut state.clone().current.public_keys);
                acc.1
                    .append(&mut state.clone().current.next_keys_data.next_key_hashes);
                acc
            },
        );

        let icp = event_generator::incept_with_next_hashes(
            pks,
            &SignatureThreshold::Simple(signature_threshold),
            npks,
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
            delegator.as_ref(),
        )
        .unwrap();

        let serialized_icp = String::from_utf8(icp.serialize()?)
            .map_err(|e| ControllerError::EventGenerationError(e.to_string()))?;

        let mut exchanges = participants
            .iter()
            .map(|id| {
                let exn = event_generator::exchange(id, &icp, ForwardTopic::Multisig)
                    .unwrap()
                    .serialize()
                    .unwrap();
                String::from_utf8(exn).unwrap()
            })
            .collect::<Vec<_>>();
        let delegation_request = delegator.map(|del| {
            String::from_utf8(
                event_generator::exchange(&del, &icp, ForwardTopic::Delegate)
                    .unwrap()
                    .serialize()
                    .unwrap(),
            )
            .unwrap()
        });
        if let Some(delegation_request) = delegation_request {
            exchanges.push(delegation_request)
        };

        Ok((serialized_icp, exchanges))
    }

    /// Join event with signature, save it in db, sends signed exn messages to
    /// witness.
    pub fn finalize_group_incept(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(&[u8], SelfSigningPrefix)>,
    ) -> Result<IdentifierPrefix, ControllerError> {
        // Join icp event with signature
        let (_, key_event) = key_event_message(&group_event).unwrap();
        if let EventType::KeyEvent(icp) = key_event {
            let own_index = self.get_index(&icp.event)?;
            let group_prefix = icp.event.get_prefix();

            self.source.finalize_key_event(&icp, &sig, own_index)?;
            self.groups.push(icp.event.get_prefix());

            let signature = AttachedSignaturePrefix {
                index: own_index as u16,
                signature: sig,
            };

            // Join exn messages with their signatures and send it to witness.
            let material_path = MaterialPath::to_path("-a".into());
            let attached_sig = vec![Signature::Transferable(
                SignerData::JustSignatures,
                vec![signature],
            )];
            exchanges.into_iter().try_for_each(|(exn, signature)| {
                let (_, parsed_exn) = exchange_message(exn).unwrap();
                if let EventType::Exn(exn) = parsed_exn {
                    let signature = vec![Signature::Transferable(
                        SignerData::LastEstablishment(self.id.clone()),
                        vec![AttachedSignaturePrefix {
                            // TODO
                            index: 0,
                            signature,
                        }],
                    )];
                    let signer_exn = Message::Op(Op::Exchange(SignedExchange {
                        exchange_message: exn,
                        signature,
                        data_signature: (material_path.clone(), attached_sig.clone()),
                    }));
                    self.source
                        .get_witnesses_at_event(&icp)?
                        // TODO for now get first witness
                        .get(0)
                        .map(|wit| {
                            self.source.send_to(
                                &IdentifierPrefix::Basic(wit.clone()),
                                keri::oobi::Scheme::Http,
                                // TODO what endpoint should be used?
                                Topic::Query(
                                    String::from_utf8(signer_exn.to_cesr().unwrap()).unwrap(),
                                ),
                            )
                        });
                    Ok(())
                } else {
                    Err(ControllerError::WrongEventTypeError)
                }
            })?;
            Ok(group_prefix)
        } else {
            Err(ControllerError::WrongEventTypeError)
        }
    }

    /// Helper function for getting the position of identifier's public key in
    /// group's current keys list.
    pub(crate) fn get_index(&self, group_event: &KeyEvent) -> Result<usize, ControllerError> {
        // TODO what if group participant is a group and has more than one
        // public key?
        let own_pk = &self
            .source
            .storage
            .get_state(&self.id)?
            .ok_or(ControllerError::UnknownIdentifierError)?
            .current
            .public_keys[0];
        match &group_event.content.event_data {
            EventData::Icp(icp) => icp
                .key_config
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
            EventData::Rot(rot) => rot
                .key_config
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
            EventData::Dip(dip) => dip
                .inception_data
                .key_config
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
            EventData::Drt(drt) => drt
                .key_config
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
            EventData::Ixn(_ixn) => self
                .source
                .storage
                .get_state(&group_event.get_prefix())?
                .ok_or(ControllerError::UnknownIdentifierError)?
                .current
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
        }
        .ok_or(ControllerError::NotGroupParticipantError)
    }

    pub fn query_own_mailbox(
        &self,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        // query own mailbox
        // let own_queries =
        Ok(witnesses
            .into_iter()
            .map(|wit| {
                QueryEvent::new_query(
                    QueryRoute::Mbx {
                        args: QueryArgsMbx {
                            // about who
                            i: self.id.clone(),
                            // who is asking
                            pre: self.id.clone(),
                            // who will get the query
                            src: IdentifierPrefix::Basic(wit.clone()),
                            topics: QueryTopics {
                                credential: 0,
                                receipt: 0,
                                replay: 0,
                                multisig: 0,
                                delegate: 0,
                                reply: 0,
                            },
                        },
                        reply_route: "".to_string(),
                    },
                    SerializationFormats::JSON,
                    &SelfAddressing::Blake3_256,
                )
                // .unwrap()
            })
            .collect::<Result<_, _>>()
            .unwrap())
    }

    pub fn query_group_mailbox(
        &self,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<QueryEvent>, ControllerError> {
        // query group mailbox
        let groups_queries = self
            .groups
            .iter()
            .map(|group_id| {
                witnesses.clone().into_iter().map(move |wit| {
                    QueryEvent::new_query(
                        QueryRoute::Mbx {
                            args: QueryArgsMbx {
                                // about who
                                i: group_id.clone(),
                                // who is asking
                                pre: self.id.clone(),
                                // who will get the query
                                src: IdentifierPrefix::Basic(wit.clone()),
                                topics: QueryTopics {
                                    credential: 0,
                                    receipt: 0,
                                    replay: 0,
                                    multisig: 0,
                                    delegate: 0,
                                    reply: 0,
                                },
                            },
                            reply_route: "".to_string(),
                        },
                        SerializationFormats::JSON,
                        &SelfAddressing::Blake3_256,
                    )
                    .unwrap()
                })
            })
            .flatten();
        Ok(groups_queries.collect())
    }

    pub fn finalize_mailbox_query(
        &mut self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        Ok(queries
            .into_iter()
            .map(|(qry, sig)| -> Result<_, ControllerError> {
                let signatures = vec![AttachedSignaturePrefix {
                    index: 0,
                    signature: sig,
                }];
                let (receipient, from_who, about_who) = match &qry.event.content.data.route {
                    QueryRoute::Log {
                        reply_route: _,
                        args,
                    } => (args.src.clone().unwrap(), None, None),
                    QueryRoute::Ksn {
                        reply_route: _,
                        args,
                    } => (args.src.clone().unwrap(), None, None),
                    QueryRoute::Mbx {
                        reply_route: _,
                        args,
                    } => (args.src.clone(), Some(&args.i), Some(&args.pre)),
                };
                let query = Op::Query(SignedQuery::new(qry.clone(), self.id.clone(), signatures));
                let qry_str = String::from_utf8(Message::Op(query.clone()).to_cesr().unwrap())
                    .map_err(|_e| ControllerError::EventParseError)?;
                let response =
                    self.source
                        .send_to(&receipient, Scheme::Http, Topic::Query(qry_str))?;
                // TODO what if other reponse than mailbox?
                let res = parse_response(&response).unwrap();
                if let PossibleResponse::Mbx(res) = res {
                    let req = if from_who == about_who {
                        // process own mailbox
                        let req = self.process_own_mailbox(&res, &self.last_asked_index)?;
                        self.last_asked_index = MailboxReminder {
                            receipt: res.receipt.len(),
                            multisig: res.multisig.len(),
                            delegate: res.delegate.len(),
                        };
                        req
                    } else {
                        // process group mailbox
                        let group_req =
                            self.process_group_mailbox(&res, &self.last_asked_groups_index)?;
                        self.last_asked_groups_index = MailboxReminder {
                            receipt: res.receipt.len(),
                            multisig: res.multisig.len(),
                            delegate: res.delegate.len(),
                        };
                        group_req
                    };
                    Ok(req)
                } else {
                    todo!()
                }
            })
            .collect::<Result<Vec<Vec<ActionRequired>>, _>>()?
            .into_iter()
            .flatten()
            .collect())
    }
}
