use std::convert::TryFrom;
use std::path::Path;
use std::slice;
use std::sync::Arc;

use keri::event::receipt::Receipt;
use keri::event::EventMessage;
use keri::event_message::event_msg_builder::ReceiptBuilder;
use keri::event_message::key_event_message::KeyEvent;
use keri::event_message::signed_event_message::{Message, SignedNontransferableReceipt};
use keri::event_parsing::message::signed_event_stream;
use keri::keys::PublicKey;
use keri::oobi::OobiManager;
use keri::processor::escrow::default_escrow_bus;
use keri::processor::event_storage::EventStorage;
use keri::processor::notification::{JustNotification, Notification, NotificationBus};
use keri::processor::responder::Responder;
use keri::processor::witness_processor::WitnessProcessor;
use keri::query::reply_event::{ReplyEvent, ReplyRoute, SignedReply};
use keri::query::{
    key_state_notice::KeyStateNotice,
    query_event::{QueryData, SignedQuery},
    ReplyType,
};

use keri::signer::Signer;
use keri::state::IdentifierState;
use keri::{
    database::sled::SledEventDatabase,
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::SerializationFormats,
    prefix::{BasicPrefix, IdentifierPrefix},
};

pub struct Watcher {
    pub prefix: BasicPrefix,
    processor: WitnessProcessor,
    storage: EventStorage,
    publisher: NotificationBus,
    responder: Arc<Responder<Notification>>,
}

impl Watcher {
    pub fn new(path: &Path, pk: PublicKey) -> Result<Self, Error> {
        let (processor, storage, mut publisher) = {
            let witness_db = Arc::new(SledEventDatabase::new(path)?);
            (
                WitnessProcessor::new(witness_db.clone()),
                EventStorage::new(witness_db.clone()),
                default_escrow_bus(witness_db),
            )
        };
        let prefix = Basic::Ed25519NT.derive(pk);
        let responder = Arc::new(Responder::new());
        publisher.register_observer(
            responder.clone(),
            vec![
                JustNotification::KeyEventAdded,
                JustNotification::ReplayLog,
                JustNotification::ReplyKsn,
                JustNotification::GetMailbox,
            ],
        );

        Ok(Self {
            prefix,
            processor,
            storage,
            publisher,
            responder,
        })
    }

    pub fn register_oobi_manager(&mut self, oobi_manager: Arc<OobiManager>) {
        self.publisher
            .register_observer(oobi_manager, vec![JustNotification::GotOobi]);
    }

    pub fn get_db_ref(&self) -> Arc<SledEventDatabase> {
        self.storage.db.clone()
    }

    pub fn respond(&self, signer: Arc<Signer>) -> Result<Vec<Message>, Error> {
        let mut response = Vec::new();
        while let Some(event) = self.responder.get_data_to_respond() {
            match event {
                Notification::KeyEventAdded(event) => {
                    let non_trans_receipt =
                        self.respond_to_key_event(event.event_message, signer.clone())?;
                    self.storage.add_mailbox_receipt(non_trans_receipt)?;
                }
                Notification::ReplayLog(id) => {
                    let mut kel = self
                        .storage
                        .get_kel_messages_with_receipts(&id)
                        .unwrap()
                        .unwrap();
                    response.append(&mut kel)
                }
                Notification::ReplyKsn(ksn_prefix) => {
                    let reply = self.get_ksn_for_prefix(&ksn_prefix, signer.clone())?;
                    response.push(Message::Reply(reply))
                }
                Notification::GetMailbox(args) => {
                    let mut mail = self.storage.get_mailbox_events(args)?;
                    response.append(&mut mail)
                }
                _ => return Err(Error::SemanticError("Wrong notification type".into())),
            }
        }
        Ok(response)
    }

    fn respond_to_key_event(
        &self,
        event_message: EventMessage<KeyEvent>,
        signer: Arc<Signer>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = signer.sign(&ser)?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message)
            .build()?;

        let signature = SelfSigning::Ed25519Sha512.derive(signature);

        let signed_rcp = SignedNontransferableReceipt::new(
            &rcp,
            Some(vec![(self.prefix.clone(), signature)]),
            None,
        );

        self.processor
            .process(Message::NontransferableRct(signed_rcp.clone()))?;
        Ok(signed_rcp)
    }

    pub fn parse_and_process(&self, msg: &[u8]) -> Result<(), Error> {
        let (_, msgs) =
            signed_event_stream(msg).map_err(|e| Error::DeserializeError(e.to_string()))?;

        for msg in msgs {
            let msg = Message::try_from(msg)?;
            self.process(slice::from_ref(&msg))?;
            // check if receipts are attached
            if let Message::Event(ev) = msg {
                if let Some(witness_receipts) = ev.witness_receipts {
                    // Create and process witness receipts
                    // TODO What timestamp should be set?
                    let id = ev.event_message.event.get_prefix();
                    let receipt = Receipt {
                        receipted_event_digest: ev.event_message.get_digest(),
                        prefix: id,
                        sn: ev.event_message.event.get_sn(),
                    };
                    let signed_receipt = SignedNontransferableReceipt::new(
                        &receipt.to_message(SerializationFormats::JSON)?,
                        None,
                        Some(witness_receipts),
                    );
                    self.process(&[Message::NontransferableRct(signed_receipt)])?;
                }
            }
        }
        Ok(())
    }

    pub fn process(&self, msg: &[Message]) -> Result<(), Error> {
        let (process_ok, process_failed): (Vec<_>, Vec<_>) = msg
            .iter()
            .map(|message| {
                self.processor
                    .process(message.clone())
                    .and_then(|not| self.publisher.notify(&not))
            })
            .partition(Result::is_ok);
        let _oks = process_ok
            .into_iter()
            .map(Result::unwrap)
            .collect::<Vec<_>>();
        let _errs = process_failed
            .into_iter()
            .map(Result::unwrap_err)
            .collect::<Vec<_>>();

        Ok(())
    }

    pub fn get_kel_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_kel(id)
    }

    pub fn get_receipts_for_prefix(&self, id: &IdentifierPrefix) -> Result<Option<Vec<u8>>, Error> {
        self.storage.get_escrowed_nt_receipts(id)
    }

    pub fn get_state_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
    ) -> Result<Option<IdentifierState>, Error> {
        self.storage.get_state(prefix)
    }

    pub fn get_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let state = self
            .get_state_for_prefix(prefix)?
            .ok_or_else(|| Error::SemanticError("No state in db".into()))?;
        let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
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

    pub fn process_signed_query(
        &self,
        qr: SignedQuery,
        signer: Arc<Signer>,
    ) -> Result<ReplyType, Error> {
        let signatures = qr.signatures;
        // check signatures
        let kc = self
            .storage
            .get_state(&qr.signer)?
            .ok_or_else(|| Error::SemanticError("No signer identifier in db".into()))?
            .current;

        if kc.verify(&qr.query.serialize()?, &signatures)? {
            // TODO check timestamps
            // unpack and check what's inside
            self.process_query(qr.query.get_query_data(), signer)
        } else {
            Err(Error::SignatureVerificationError)
        }
    }

    fn process_query(&self, qr: QueryData, signer: Arc<Signer>) -> Result<ReplyType, Error> {
        use keri::query::query_event::QueryRoute;

        match qr.route {
            QueryRoute::Log { args: data, .. } => Ok(ReplyType::Kel(
                self.storage
                    .get_kel_messages_with_receipts(&data.i)?
                    .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?,
            )),
            QueryRoute::Ksn { args: data, .. } => {
                let i = data.i;
                // return reply message with ksn inside
                let state = self
                    .storage
                    .get_state(&i)?
                    .ok_or_else(|| Error::SemanticError("No id in database".into()))?;
                let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;
                let signature = signer.sign(&rpy.serialize()?)?;
                let rpy = SignedReply::new_nontrans(
                    rpy,
                    self.prefix.clone(),
                    SelfSigning::Ed25519Sha512.derive(signature),
                );
                Ok(ReplyType::Rep(rpy))
            }
            QueryRoute::Mbx { .. } => {
                // TODO: remove whole fn?
                todo!("process MBX query")
            }
        }
    }
}
