use std::{
    convert::TryInto,
    fmt,
    path::Path,
    sync::{Arc, Mutex},
};

use cesrox::{cesr_proof::MaterialPath, parse, primitives::CesrPrimitive};
use said::derivation::{HashFunction, HashFunctionCode};
use serde::{Deserialize, Serialize};
use version::serialization_info::SerializationFormats;

use super::{event_generator, prelude::Message, process_message};
#[cfg(feature = "mailbox")]
use crate::mailbox::{
    exchange::{Exchange, ForwardTopic, FwdArgs, SignedExchange},
    MailboxResponse,
};
use crate::{
    actor::parse_event_stream,
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event::{
        event_data::EventData,
        sections::{
            seal::{EventSeal, Seal},
            threshold::SignatureThreshold,
        },
        KeyEvent,
    },
    event_message::{
        cesr_adapter::EventType,
        signature::{Signature, SignerData},
        signed_event_message::{Notice, Op, SignedEventMessage, SignedNontransferableReceipt},
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{
            default_escrow_bus, DelegationEscrow, EscrowConfig, OutOfOrderEscrow,
            PartiallyWitnessedEscrow,
        },
        event_storage::EventStorage,
        Processor,
    },
    signer::KeyManager,
    state::IdentifierState,
};

#[cfg(feature = "oobi")]
use crate::oobi::{OobiManager, Role};

#[cfg(feature = "query")]
use super::parse_reply_stream;
#[cfg(feature = "query")]
use crate::query::{
    query_event::{QueryArgs, QueryArgsMbx, QueryEvent, QueryRoute, QueryTopics, SignedQuery},
    reply_event::SignedReply,
};

#[cfg(feature = "query")]
#[derive(PartialEq, Debug, Clone)]
pub enum PossibleResponse {
    Kel(Vec<Message>),
    Mbx(MailboxResponse),
    Ksn(SignedReply),
}

impl PossibleResponse {
    fn display(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            PossibleResponse::Kel(kel) => kel
                .iter()
                .map(|message| -> Result<_, Error> { message.to_cesr() })
                .collect::<Result<Vec<Vec<u8>>, Error>>()?
                .concat(),
            PossibleResponse::Mbx(mbx) => {
                let receipts_stream = mbx
                    .receipt
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::NontransferableRct(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                let multisig_stream = mbx
                    .multisig
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::Event(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                let delegate_stream = mbx
                    .delegate
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::Event(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                #[derive(Serialize)]
                struct GroupedResponse {
                    receipt: String,
                    multisig: String,
                    delegate: String,
                }
                serde_json::to_vec(&GroupedResponse {
                    receipt: String::from_utf8(receipts_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                    multisig: String::from_utf8(multisig_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                    delegate: String::from_utf8(delegate_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                })
                .map_err(|_| Error::JsonDeserError)?
            }
            PossibleResponse::Ksn(ksn) => Message::Op(Op::Reply(ksn.clone())).to_cesr()?,
        })
    }
}

#[cfg(feature = "query")]
pub fn parse_response(response: &str) -> Result<PossibleResponse, Error> {
    Ok(match parse_mailbox_response(response) {
        Err(_) => match parse_reply_stream(response.as_bytes()) {
            Ok(rep) => PossibleResponse::Ksn(rep[0].clone()),
            Err(_e) => {
                let events = parse_event_stream(response.as_bytes())?;
                PossibleResponse::Kel(events)
            }
        },
        Ok(res) => res,
    })
}

#[cfg(feature = "mailbox")]
pub fn parse_mailbox_response(response: &str) -> Result<PossibleResponse, Error> {
    #[derive(Deserialize, Debug)]
    struct GroupedResponse {
        receipt: String,
        multisig: String,
        delegate: String,
    }
    let res: GroupedResponse =
        serde_json::from_str(&response).map_err(|_| Error::JsonDeserError)?;
    let receipts = parse_event_stream(res.receipt.as_bytes())?
        .into_iter()
        .map(|rct| {
            if let Message::Notice(Notice::NontransferableRct(rct)) = rct {
                rct
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    let multisig = parse_event_stream(res.multisig.as_bytes())?
        .into_iter()
        .map(|msg| {
            if let Message::Notice(Notice::Event(event)) = msg {
                event
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    let delegate = parse_event_stream(res.delegate.as_bytes())?
        .into_iter()
        .map(|msg| {
            if let Message::Notice(Notice::Event(event)) = msg {
                event
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    Ok(PossibleResponse::Mbx(MailboxResponse {
        receipt: receipts,
        multisig: multisig,
        delegate,
    }))
}

impl fmt::Display for PossibleResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = self.display().map_err(|_e| fmt::Error)?;
        f.write_str(&String::from_utf8(str).map_err(|_e| fmt::Error)?)?;
        Ok(())
    }
}

/// Helper struct for events generation, signing and processing.
/// Used in tests.
pub struct SimpleController<K: KeyManager + 'static> {
    prefix: IdentifierPrefix,
    pub key_manager: Arc<Mutex<K>>,
    processor: BasicProcessor,
    oobi_manager: OobiManager,
    pub storage: EventStorage,
    pub groups: Vec<IdentifierPrefix>,
    pub not_fully_witnessed_escrow: Arc<PartiallyWitnessedEscrow>,
    pub ooo_escrow: Arc<OutOfOrderEscrow>,
    pub delegation_escrow: Arc<DelegationEscrow>,
}

impl<K: KeyManager> SimpleController<K> {
    // incept a state and keys
    pub fn new(
        db: Arc<SledEventDatabase>,
        escrow_db: Arc<EscrowDb>,
        key_manager: Arc<Mutex<K>>,
        oobi_db_path: &Path,
        escrow_config: EscrowConfig,
    ) -> Result<SimpleController<K>, Error> {
        let (not_bus, (ooo, _, partially_witnesses, del_escrow)) =
            default_escrow_bus(db.clone(), escrow_db, escrow_config);
        let processor = BasicProcessor::new(db.clone(), Some(not_bus));

        Ok(SimpleController {
            prefix: IdentifierPrefix::default(),
            key_manager,
            oobi_manager: OobiManager::new(oobi_db_path),
            processor,
            storage: EventStorage::new(db),
            groups: vec![],
            not_fully_witnessed_escrow: partially_witnesses,
            ooo_escrow: ooo,
            delegation_escrow: del_escrow,
        })
    }

    /// Getter of the instance prefix
    ///
    pub fn prefix(&self) -> &IdentifierPrefix {
        &self.prefix
    }

    pub fn get_kel(&self) -> Option<String> {
        match self.storage.get_kel_messages(self.prefix()) {
            Ok(Some(kel)) => Some(
                String::from_utf8(
                    kel.iter()
                        .map(|s| Message::Notice(s.clone()).to_cesr().unwrap())
                        .flatten()
                        .collect(),
                )
                .unwrap(),
            ),
            _ => None,
        }
    }

    pub fn incept(
        &mut self,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<&IdentifierPrefix>,
    ) -> Result<SignedEventMessage, Error> {
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let icp = event_generator::incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            initial_witness.unwrap_or_default(),
            witness_threshold.unwrap_or(0),
            delegator,
        )
        .unwrap();
        let signature = km.sign(icp.as_bytes())?;
        let key_event = parse(icp.as_bytes()).unwrap().1.payload;
        let signed = if let EventType::KeyEvent(icp) = key_event.try_into()? {
            icp.sign(
                vec![IndexedSignature::new_both_same(
                    SelfSigningPrefix::Ed25519Sha512(signature),
                    0,
                )],
                None,
                None,
            )
        } else {
            unreachable!()
        };

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        self.prefix = signed.event_message.data.get_prefix();
        // No need to generate receipt

        Ok(signed)
    }

    pub fn query_ksn(&self, prefix: &IdentifierPrefix) -> Result<Op, Error> {
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
            HashFunctionCode::Blake3_256,
        )?;

        // sign message by bob
        let signature = IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(
                Arc::clone(&self.key_manager)
                    .lock()
                    .unwrap()
                    .sign(&serde_json::to_vec(&qry).unwrap())?,
            ),
            0,
        );
        // Qry message signed by Bob
        Ok(Op::Query(SignedQuery::new(
            qry,
            self.prefix().clone(),
            vec![signature],
        )))
    }

    pub fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<Op, Error> {
        let end_role =
            event_generator::generate_end_role(&self.prefix(), watcher_id, Role::Watcher, true)
                .unwrap();
        let sed: Vec<u8> = end_role.encode()?;
        let sig = self.key_manager.clone().lock().unwrap().sign(&sed)?;
        let att_sig = IndexedSignature::new_both_same(SelfSigningPrefix::Ed25519Sha512(sig), 0);

        let oobi_rpy = SignedReply::new_trans(
            end_role,
            self.storage
                .get_last_establishment_event_seal(self.prefix())?
                .unwrap(),
            vec![att_sig],
        );
        self.oobi_manager.process_oobi(&oobi_rpy).unwrap();
        let signed_rpy = Op::Reply(oobi_rpy);

        Ok(signed_rpy)
    }

    pub fn rotate(
        &mut self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<u64>,
    ) -> Result<SignedEventMessage, Error> {
        let rot = self.make_rotation(witness_to_add, witness_to_remove, witness_threshold)?;
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let signature = km.sign(rot.as_bytes())?;

        let key_event = parse(rot.as_bytes()).unwrap().1.payload;

        let signed = if let EventType::KeyEvent(rot) = key_event.try_into()? {
            rot.sign(
                vec![IndexedSignature::new_both_same(
                    SelfSigningPrefix::Ed25519Sha512(signature),
                    0,
                )],
                None,
                None,
            )
        } else {
            unreachable!()
        };

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        Ok(signed)
    }

    fn make_rotation(
        &self,
        witness_to_add: Option<&[BasicPrefix]>,
        witness_to_remove: Option<&[BasicPrefix]>,
        witness_threshold: Option<u64>,
    ) -> Result<String, Error> {
        let mut km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        km.rotate()?;
        let state = self
            .storage
            .get_state(&self.prefix)?
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

        Ok(event_generator::rotate(
            state,
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            witness_to_add.unwrap_or_default().to_vec(),
            witness_to_remove.unwrap_or_default().into(),
            witness_threshold.unwrap_or(0),
        )
        .unwrap())
    }

    pub fn anchor(&self, seal: &[Seal]) -> Result<SignedEventMessage, Error> {
        let state = self
            .storage
            .get_state(self.prefix())?
            .ok_or(Error::SemanticError("missing state".into()))?;
        let ixn = event_generator::anchor_with_seal(state, seal)?;
        // .map_err(|e| Error::SemanticError(e.to_string()))?;
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        let signature = km.sign(&ixn.encode()?)?;

        let signed = ixn.sign(
            vec![IndexedSignature::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                0,
            )],
            None,
            None,
        );

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        Ok(signed)
    }

    pub fn anchor_group(
        &self,
        group_id: &IdentifierPrefix,
        seals: &[Seal],
    ) -> Result<SignedEventMessage, Error> {
        if self.groups.contains(group_id) {
            let state = self
                .storage
                .get_state(group_id)?
                .ok_or(Error::SemanticError("missing state".into()))?;
            let ixn = event_generator::anchor_with_seal(state, seals)
                .map_err(|e| Error::SemanticError(e.to_string()))?;
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            let signature = km.sign(&ixn.encode()?)?;

            let attached_signature = IndexedSignature::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(signature),
                self.get_index(&ixn.data)? as u16,
            );
            let signed = ixn.sign(vec![attached_signature], None, None);

            self.processor
                .process_notice(&Notice::Event(signed.clone()))?;

            Ok(signed)
        } else {
            Err(Error::SemanticError("Not group particiant".into()))
        }
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), Error> {
        let (_process_ok, _process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                process_message(
                    message.clone(),
                    &self.oobi_manager,
                    &self.processor,
                    &self.storage,
                )
            })
            .partition(Result::is_ok);

        Ok(())
    }

    /// Returns position of identifier's public key in group's current keys
    /// list.
    fn get_index(&self, group_event: &KeyEvent) -> Result<usize, Error> {
        // TODO what if group participant is a group and has more than one
        // public key?
        let own_pk = &self
            .get_state()?
            .ok_or(Error::SemanticError("Unknown state".into()))?
            .current
            .public_keys[0];
        match &group_event.event_data {
            EventData::Icp(icp) => icp
                .key_config
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
            EventData::Rot(rot) => {
                let own_npk = &self
                    .get_state()?
                    .ok_or(Error::SemanticError("Unknown state".into()))?
                    .current
                    .next_keys_data
                    .next_key_hashes[0];
                rot.key_config
                    .public_keys
                    .iter()
                    .position(|pk| own_npk.verify_binding(pk.to_str().as_bytes()))
            }
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
                .storage
                .get_state(&group_event.get_prefix())?
                .ok_or(Error::SemanticError("Unknown state".into()))?
                .current
                .public_keys
                .iter()
                .position(|pk| pk == own_pk),
        }
        .ok_or(Error::SemanticError("Not group participant".into()))
    }

    /// Checks multisig event and sign it if it wasn't sign by controller
    /// earlier.
    pub fn process_multisig(
        &mut self,
        event: SignedEventMessage,
    ) -> Result<Option<SignedEventMessage>, Error> {
        self.process(&[Message::Notice(Notice::Event(event.clone()))])?;
        let group_prefix = event.event_message.data.get_prefix();

        // Process partially signed group icp
        let index = self.get_index(&event.event_message.data)?;

        // sign and process inception event
        let second_signature = IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(
                self.key_manager
                    .lock()
                    .unwrap()
                    .sign(&event.event_message.encode()?)?,
            ),
            index as u16,
        );
        let signed_icp = event
            .clone()
            .event_message
            .sign(vec![second_signature], None, None);
        self.groups.push(group_prefix);
        self.process(&[Message::Notice(Notice::Event(signed_icp.clone()))])?;
        Ok(Some(signed_icp.clone()))
    }

    pub fn get_state(&self) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(&self.prefix)
    }

    pub fn get_state_for_id(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(id)
    }

    /// Generates group inception event signed by controller and exchange
    /// messages to group participants from `participants` argument.
    pub fn group_incept(
        &mut self,
        participants: Vec<IdentifierPrefix>,
        signature_threshold: &SignatureThreshold,
        initial_witness: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<IdentifierPrefix>,
    ) -> Result<(SignedEventMessage, Vec<SignedExchange>), Error> {
        let signed = {
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            let next_key_hash = HashFunction::from(HashFunctionCode::Blake3_256).derive(
                BasicPrefix::Ed25519(km.next_public_key())
                    .to_str()
                    .as_bytes(),
            );
            let (pks, npks) = participants.iter().fold(
                (
                    vec![BasicPrefix::Ed25519(km.public_key())],
                    vec![next_key_hash],
                ),
                |mut acc, id| {
                    let state = self.storage.get_state(id).unwrap().unwrap();
                    acc.0.append(&mut state.clone().current.public_keys);
                    acc.1
                        .append(&mut state.clone().current.next_keys_data.next_key_hashes);
                    acc
                },
            );

            let icp = &event_generator::incept_with_next_hashes(
                pks,
                signature_threshold,
                npks,
                initial_witness.unwrap_or_default(),
                witness_threshold.unwrap_or(0),
                delegator.as_ref(),
            )
            .unwrap()
            .encode()?;

            let signature = km.sign(&icp)?;
            let key_event = parse(&icp).unwrap().1.payload;
            if let EventType::KeyEvent(icp) = key_event.try_into()? {
                icp.sign(
                    vec![IndexedSignature::new_both_same(
                        SelfSigningPrefix::Ed25519Sha512(signature),
                        0,
                    )],
                    None,
                    None,
                )
            } else {
                unreachable!()
            }
        };

        self.processor
            .process_notice(&Notice::Event(signed.clone()))?;

        self.groups.push(signed.event_message.data.get_prefix());

        let exchanges = participants
            .iter()
            .map(|id| {
                self.create_forward_message(id, &signed, ForwardTopic::Multisig)
                    .unwrap()
            })
            .collect();

        Ok((signed, exchanges))
    }

    #[cfg(feature = "mailbox")]
    pub fn create_forward_message(
        &self,
        receipient: &IdentifierPrefix,
        data: &SignedEventMessage,
        topic: ForwardTopic,
    ) -> Result<SignedExchange, Error> {
        let exn_message = Exchange::Fwd {
            args: FwdArgs {
                recipient_id: receipient.clone(),
                topic,
            },
            to_forward: data.event_message.clone(),
        }
        .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256)?;

        let sigs = vec![Signature::Transferable(
            SignerData::JustSignatures,
            data.signatures.clone(),
        )];
        let sigs = if let Some(witness_sigs) = data
            .witness_receipts
            .as_ref()
            .map(|sigs| sigs.iter().map(|t| Signature::NonTransferable(t.clone())))
        {
            witness_sigs.chain(sigs.into_iter()).collect::<Vec<_>>()
        } else {
            sigs
        };
        let mat = MaterialPath::to_path("-a".into());
        let ssp = {
            SelfSigningPrefix::Ed25519Sha512(
                self.key_manager
                    .lock()
                    .unwrap()
                    .sign(&exn_message.encode()?)?,
            )
        };

        let exn_sig = IndexedSignature::new_both_same(ssp, 0);
        let sigg = Signature::Transferable(
            SignerData::LastEstablishment(self.prefix.clone()),
            vec![exn_sig],
        );

        Ok(SignedExchange {
            exchange_message: exn_message,
            signature: vec![sigg],
            data_signature: (mat, sigs),
        })
    }

    #[cfg(feature = "mailbox")]
    pub fn query_mailbox(&self, witness: &BasicPrefix) -> SignedQuery {
        let qry_msg = QueryEvent::new_query(
            QueryRoute::Mbx {
                args: QueryArgsMbx {
                    i: self.prefix.clone(),
                    pre: self.prefix.clone(),
                    src: IdentifierPrefix::Basic(witness.clone()),
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
            HashFunctionCode::Blake3_256,
        )
        .unwrap();
        let signature = self
            .key_manager
            .lock()
            .unwrap()
            .sign(&qry_msg.encode().unwrap())
            .unwrap();
        let signatures = vec![IndexedSignature::new_both_same(
            SelfSigningPrefix::Ed25519Sha512(signature),
            0,
        )];
        let mbx_msg = SignedQuery::new(qry_msg, self.prefix.clone().clone(), signatures);
        mbx_msg
    }

    #[cfg(feature = "mailbox")]
    pub fn query_groups_mailbox(&self, witness: &BasicPrefix) -> Vec<SignedQuery> {
        self.groups
            .iter()
            .map(|id| {
                let qry_msg = QueryEvent::new_query(
                    QueryRoute::Mbx {
                        args: QueryArgsMbx {
                            i: id.clone(),
                            pre: self.prefix.clone(),
                            src: IdentifierPrefix::Basic(witness.clone()),
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
                    HashFunctionCode::Blake3_256,
                )
                .unwrap();
                let signature = self
                    .key_manager
                    .lock()
                    .unwrap()
                    .sign(&qry_msg.encode().unwrap())
                    .unwrap();
                let signatures = vec![IndexedSignature::new_both_same(
                    SelfSigningPrefix::Ed25519Sha512(signature),
                    0,
                )];
                SignedQuery::new(qry_msg, self.prefix.clone(), signatures)
            })
            .collect()
    }

    /// Returns exn message that contains signed multisig event and will be
    /// forward to group identifier's mailbox.
    pub fn process_own_multisig(
        &mut self,
        event: SignedEventMessage,
    ) -> Result<SignedExchange, Error> {
        let signed_icp = self.process_multisig(event)?.unwrap();
        let receipient = signed_icp.event_message.data.get_prefix();
        // Construct exn message (will be stored in group identidfier mailbox)
        self.create_forward_message(&receipient, &signed_icp, ForwardTopic::Multisig)
    }

    /// If leader and event is fully signed, return event to forward to witness.
    pub fn process_group_multisig(
        &self,
        event: SignedEventMessage,
    ) -> Result<Option<SignedEventMessage>, Error> {
        self.process(&[Message::Notice(Notice::Event(event.clone()))])?;

        let id = event.event_message.data.get_prefix();
        let fully_signed_event = self.not_fully_witnessed_escrow.get_event_by_sn_and_digest(
            event.event_message.data.get_sn(),
            &id,
            &event.event_message.get_digest(),
        );

        let own_index = self.get_index(&event.event_message.data)?;
        // Elect the leader
        // Leader is identifier with minimal index among all participants who
        // sign event. He will send message to witness.
        Ok(fully_signed_event.and_then(|ev| {
            ev.signatures
                .iter()
                .map(|at| at.index.current())
                .min()
                .and_then(|index| {
                    if index as usize == own_index {
                        Some(ev)
                    } else {
                        None
                    }
                })
        }))
    }

    /// Create delegating event, pack it in exn message (delegate topic).
    pub fn process_own_delegate(
        &mut self,
        event_to_confirm: SignedEventMessage,
    ) -> Result<SignedExchange, Error> {
        self.process(&[Message::Notice(Notice::Event(event_to_confirm.clone()))])?;
        let id = event_to_confirm.event_message.data.get_prefix();

        let seal = Seal::Event(EventSeal {
            prefix: id.clone(),
            sn: event_to_confirm.event_message.data.get_sn(),
            event_digest: event_to_confirm.event_message.get_digest(),
        });

        let ixn = self.anchor(&vec![seal])?;
        self.create_forward_message(&id, &ixn, ForwardTopic::Delegate)
    }

    /// Create delegating event, pack it in exn message to group identifier (multisig topic).
    pub fn process_group_delegate(
        &self,
        event_to_confirm: SignedEventMessage,
        group_id: &IdentifierPrefix,
    ) -> Result<SignedExchange, Error> {
        self.process(&[Message::Notice(Notice::Event(event_to_confirm.clone()))])?;
        let id = event_to_confirm.event_message.data.get_prefix();

        let seal = Seal::Event(EventSeal {
            prefix: id.clone(),
            sn: event_to_confirm.event_message.data.get_sn(),
            event_digest: event_to_confirm.event_message.get_digest(),
        });

        let ixn = self.anchor_group(group_id, &vec![seal])?;
        self.create_forward_message(&group_id, &ixn, ForwardTopic::Multisig)
    }

    pub fn process_receipt(&self, receipt: SignedNontransferableReceipt) -> Result<(), Error> {
        self.process(&[Message::Notice(Notice::NontransferableRct(receipt))])?;
        Ok(())
    }
}
