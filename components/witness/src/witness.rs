use std::{path::Path, sync::Arc};

use keri::{
    actor::{prelude::*, process_reply, process_signed_query},
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::EventMessage,
    event_message::{
        event_msg_builder::ReceiptBuilder,
        key_event_message::KeyEvent,
        signed_event_message::{Message, Op, SignedNontransferableReceipt},
    },
    oobi::{LocationScheme, OobiManager},
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::notification::{Notification, NotificationBus, Notifier},
    query::{
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
};

use crate::witness_processor::WitnessProcessor;

pub struct WitnessReceiptGenerator {
    pub prefix: BasicPrefix,
    pub signer: Arc<Signer>,
    pub storage: EventStorage,
}

impl Notifier for WitnessReceiptGenerator {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(event) => {
                let non_trans_receipt =
                    self.respond_to_key_event(&event.event_message, self.signer.clone())?;
                let prefix = &non_trans_receipt.body.event.prefix.clone();
                self.storage
                    .db
                    .add_receipt_nt(non_trans_receipt.clone(), prefix)?;
                bus.notify(&Notification::ReceiptAccepted)?;
                self.storage.add_mailbox_receipt(non_trans_receipt)?;
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

impl WitnessReceiptGenerator {
    pub fn new(signer: Arc<Signer>, db: Arc<SledEventDatabase>) -> Self {
        let storage = EventStorage::new(db);
        let prefix = Basic::Ed25519.derive(signer.public_key());
        Self {
            prefix,
            signer,
            storage,
        }
    }

    fn respond_to_key_event(
        &self,
        event_message: &EventMessage<KeyEvent>,
        signer: Arc<Signer>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = signer.sign(&ser)?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message.clone())
            .build()?;

        let signature = SelfSigning::Ed25519Sha512.derive(signature);

        let signed_rcp = SignedNontransferableReceipt::new(
            &rcp,
            Some(vec![(self.prefix.clone(), signature)]),
            None,
        );

        Ok(signed_rcp)
    }
}

pub struct Witness {
    pub prefix: BasicPrefix,
    pub processor: WitnessProcessor,
    pub event_storage: EventStorage,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    pub receipt_generator: Arc<WitnessReceiptGenerator>,
}

impl Witness {
    pub fn new(signer: Arc<Signer>, event_path: &Path, oobi_path: &Path) -> Result<Self, Error> {
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let db = Arc::new(SledEventDatabase::new(event_path)?);
        let mut witness_processor = WitnessProcessor::new(db.clone());
        let event_storage = EventStorage::new(db.clone());

        let receipt_generator = Arc::new(WitnessReceiptGenerator::new(signer.clone(), db.clone()));
        witness_processor.register_observer(receipt_generator.clone())?;
        Ok(Self {
            prefix,
            processor: witness_processor,
            signer: signer,
            event_storage,
            receipt_generator,
            oobi_manager: OobiManager::new(oobi_path),
        })
    }
    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or(Ok(Signer::new()))?,
        );
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let witness = Witness::new(signer.clone(), event_db_path, oobi_db_path)?;
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
        witness.oobi_manager.save_oobi(&signed_reply)?;
        Ok(witness)
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(match self.oobi_manager.get_loc_scheme(eid)? {
            Some(oobis_to_sign) => Some(
                oobis_to_sign
                    .iter()
                    .map(|oobi_to_sing| {
                        let signature =
                            self.signer.sign(oobi_to_sing.serialize().unwrap()).unwrap();
                        SignedReply::new_nontrans(
                            oobi_to_sing.clone(),
                            self.prefix.clone(),
                            SelfSigning::Ed25519Sha512.derive(signature),
                        )
                    })
                    .collect(),
            ),
            None => None,
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

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: Message) -> Result<Option<Vec<Message>>, Error> {
        let response = match msg.clone() {
            Message::Op(op) => Some(self.process_op(op)?),
            Message::Notice(notice) => {
                self.processor.process_notice(&notice)?;
                None
            }
        };

        Ok(response)
    }

    fn process_op(&self, op: Op) -> Result<Vec<Message>, Error> {
        let mut responses = Vec::new();

        match op {
            Op::Query(qry) => {
                let response = process_signed_query(qry, &self.event_storage).unwrap();
                match response {
                    ReplyType::Ksn(ksn) => {
                        let rpy = ReplyEvent::new_reply(
                            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                            SelfAddressing::Blake3_256,
                            SerializationFormats::JSON,
                        )?;

                        let signature =
                            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
                        let reply = Message::Op(Op::Reply(SignedReply::new_nontrans(
                            rpy,
                            self.prefix.clone(),
                            signature,
                        )));
                        responses.push(reply);
                    }
                    ReplyType::Kel(msgs) | ReplyType::Mbx(msgs) => responses.extend(msgs),
                };
            }
            Op::Reply(rpy) => {
                process_reply(
                    rpy,
                    &self.oobi_manager,
                    &self.processor,
                    &self.event_storage,
                )?;
            }
        }

        Ok(responses)
    }

    pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<Vec<Message>, Error> {
        Ok(parse_event_stream(input_stream)?
            .into_iter()
            .map(|message| self.process(message))
            // TODO: avoid unwrap
            .map(|d| d.unwrap())
            .flatten()
            .flatten()
            .collect())
    }
}
