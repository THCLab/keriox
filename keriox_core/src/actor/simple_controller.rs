use std::{
    convert::TryInto,
    sync::{Arc, Mutex},
};

#[cfg(feature = "storage-redb")]
use crate::database::redb::RedbDatabase;
use crate::{
    database::{EscrowCreator, EventDatabase},
    processor::escrow::{
        maybe_out_of_order_escrow::MaybeOutOfOrderEscrow,
        partially_witnessed_escrow::PartiallyWitnessedEscrow,
    },
    query::{mailbox::SignedMailboxQuery, query_event::LogsQueryArgs},
};
use cesrox::{cesr_proof::MaterialPath, parse, primitives::CesrPrimitive};
use said::derivation::{HashFunction, HashFunctionCode};
use said::version::format::SerializationFormats;

use super::{
    event_generator, prelude::Message, process_notice, process_signed_exn, process_signed_oobi,
};
#[cfg(feature = "mailbox")]
use crate::mailbox::exchange::{Exchange, ForwardTopic, FwdArgs, SignedExchange};
use crate::{
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
        escrow::{default_escrow_bus, delegation_escrow::DelegationEscrow, EscrowConfig},
        event_storage::EventStorage,
        Processor,
    },
    signer::KeyManager,
    state::IdentifierState,
};

#[cfg(feature = "oobi-manager")]
use crate::oobi::Role;
#[cfg(feature = "oobi-manager")]
use crate::oobi_manager::OobiManager;

#[cfg(feature = "query")]
use crate::query::{
    query_event::{QueryEvent, QueryRoute, SignedKelQuery, SignedQueryMessage},
    reply_event::SignedReply,
};

/// Helper struct for events generation, signing and processing.
/// Used in tests.
pub struct SimpleController<K: KeyManager + 'static, D: EventDatabase + EscrowCreator> {
    prefix: IdentifierPrefix,
    pub key_manager: Arc<Mutex<K>>,
    processor: BasicProcessor<D>,
    oobi_manager: OobiManager,
    pub storage: EventStorage<D>,
    pub groups: Vec<IdentifierPrefix>,
    pub not_fully_witnessed_escrow: Arc<PartiallyWitnessedEscrow<D>>,
    pub ooo_escrow: Arc<MaybeOutOfOrderEscrow<D>>,
    pub delegation_escrow: Arc<DelegationEscrow<D>>,
}

// impl<K: KeyManager, D: EventDatabase + Send + Sync + 'static> SimpleController<K, D> {
#[cfg(feature = "storage-redb")]
impl<K: KeyManager> SimpleController<K, RedbDatabase> {
    // incept a state and keys
    pub fn new(
        event_db: Arc<RedbDatabase>,
        key_manager: Arc<Mutex<K>>,
        escrow_config: EscrowConfig,
    ) -> Result<SimpleController<K, RedbDatabase>, Error> {
        let (not_bus, (ooo, _, partially_witnesses, del_escrow, _duplicates)) =
            default_escrow_bus(event_db.clone(), escrow_config);
        let processor = BasicProcessor::new(event_db.clone(), Some(not_bus));

        Ok(SimpleController {
            prefix: IdentifierPrefix::default(),
            key_manager,
            oobi_manager: OobiManager::new(event_db.clone()),
            processor,
            storage: EventStorage::new(event_db.clone()),
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
        let query_args = LogsQueryArgs {
            i: prefix.clone(),
            s: None,
            src: None,
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
        Ok(Op::Query(
            crate::query::query_event::SignedQueryMessage::KelQuery(SignedKelQuery::new_trans(
                qry,
                self.prefix().clone(),
                vec![signature],
            )),
        ))
    }

    #[cfg(feature = "oobi")]
    pub fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<Op, Error> {
        let end_role =
            event_generator::generate_end_role(&self.prefix(), watcher_id, Role::Watcher, true);
        let sed: Vec<u8> = end_role.encode()?;
        let sig = self.key_manager.clone().lock().unwrap().sign(&sed)?;
        let att_sig = IndexedSignature::new_both_same(SelfSigningPrefix::Ed25519Sha512(sig), 0);

        let oobi_rpy = SignedReply::new_trans(
            end_role,
            self.storage
                .get_last_establishment_event_seal(self.prefix())
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
            .get_state(&self.prefix)
            .ok_or_else(|| Error::SemanticError("There is no state".into()))?;

        Ok(event_generator::rotate(
            state,
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            1,
            witness_to_add.unwrap_or_default().to_vec(),
            witness_to_remove.unwrap_or_default().into(),
            witness_threshold.unwrap_or(0),
        )
        .unwrap())
    }

    pub fn anchor(&self, seal: &[Seal]) -> Result<SignedEventMessage, Error> {
        let state = self
            .storage
            .get_state(self.prefix())
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
                .get_state(group_id)
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
            .map(|message| match message {
                Message::Notice(notice) => process_notice(notice.to_owned(), &self.processor),
                Message::Op(op) => match op {
                    Op::Exchange(exn) => process_signed_exn(exn.to_owned(), &self.storage),
                    Op::Reply(rpy) => process_signed_oobi(&rpy, &self.oobi_manager, &self.storage),
                    Op::Query(_) => todo!(),
                },
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
            .get_state()
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
                    .get_state()
                    .ok_or(Error::SemanticError("Unknown state".into()))?
                    .current
                    .next_keys_data
                    .next_keys_hashes()[0];
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
                .get_state(&group_event.get_prefix())
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

    pub fn get_state(&self) -> Option<IdentifierState> {
        self.storage.get_state(&self.prefix)
    }

    pub fn get_state_for_id(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
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
                    let state = self.storage.get_state(id).unwrap();
                    acc.0.append(&mut state.clone().current.public_keys);
                    acc.1
                        .append(&mut state.clone().current.next_keys_data.next_keys_hashes());
                    acc
                },
            );

            let icp = &event_generator::incept_with_next_hashes(
                pks,
                signature_threshold,
                npks,
                signature_threshold,
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
        .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256);

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
    pub fn query_mailbox(&self, witness: &BasicPrefix) -> SignedQueryMessage {
        use crate::query::mailbox::{MailboxQuery, MailboxRoute, QueryArgsMbx, QueryTopics};

        let qry_msg = MailboxQuery::new_query(
            MailboxRoute::Mbx {
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
        );
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
        let mbx_msg =
            SignedMailboxQuery::new_trans(qry_msg, self.prefix.clone().clone(), signatures);
        SignedQueryMessage::MailboxQuery(mbx_msg)
    }

    #[cfg(feature = "mailbox")]
    pub fn query_groups_mailbox(&self, witness: &BasicPrefix) -> Vec<SignedQueryMessage> {
        use crate::query::mailbox::{MailboxQuery, MailboxRoute, QueryArgsMbx, QueryTopics};

        self.groups
            .iter()
            .map(|id| {
                let qry_msg = MailboxQuery::new_query(
                    MailboxRoute::Mbx {
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
                );
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
                SignedQueryMessage::MailboxQuery(SignedMailboxQuery::new_trans(
                    qry_msg,
                    self.prefix.clone(),
                    signatures,
                ))
            })
            .collect()
    }

    /// Returns exn message that contains signed multisig event and will be
    /// forward to group identifier's mailbox.
    #[cfg(feature = "mailbox")]
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
            &event.event_message.digest()?,
        )?;

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

        let seal = Seal::Event(EventSeal::new(
            id.clone(),
            event_to_confirm.event_message.data.get_sn(),
            event_to_confirm.event_message.digest()?,
        ));

        let ixn = self.anchor(&vec![seal])?;
        #[cfg(feature = "mailbox")]
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

        let seal = Seal::Event(EventSeal::new(
            id.clone(),
            event_to_confirm.event_message.data.get_sn(),
            event_to_confirm.event_message.digest()?,
        ));

        let ixn = self.anchor_group(group_id, &vec![seal])?;
        #[cfg(feature = "mailbox")]
        self.create_forward_message(&group_id, &ixn, ForwardTopic::Multisig)
    }

    pub fn process_receipt(&self, receipt: SignedNontransferableReceipt) -> Result<(), Error> {
        self.process(&[Message::Notice(Notice::NontransferableRct(receipt))])?;
        Ok(())
    }
}
