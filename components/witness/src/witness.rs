use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use keri::{
    actor::{
        error::ActorError, parse_exchange_stream, parse_notice_stream, parse_query_stream,
        parse_reply_stream, prelude::*, process_reply, process_signed_exn, process_signed_query,
        simple_controller::PossibleResponse,
    },
    error::Error,
    event::KeyEvent,
    event_message::{
        event_msg_builder::ReceiptBuilder,
        msg::KeriEvent,
        signature::Nontransferable,
        signed_event_message::{Notice, SignedNontransferableReceipt},
    },
    mailbox::MailboxResponse,
    oobi::{LocationScheme, OobiManager},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::notification::{Notification, NotificationBus, Notifier},
    query::{
        query_event::{QueryArgsMbx, QueryTopics},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    sai::derivation::SelfAddressing,
    signer::Signer,
};

use crate::witness_processor::{WitnessEscrowConfig, WitnessProcessor};

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
                let prefix = &event.event_message.data.get_prefix(); //&non_trans_receipt.body.event.prefix.clone();
                self.storage
                    .db
                    .add_receipt_nt(non_trans_receipt.clone(), prefix)?;
                bus.notify(&Notification::ReceiptAccepted)?;
                self.storage.add_mailbox_receipt(non_trans_receipt)?;
                Ok(())
            }
            Notification::PartiallyWitnessed(prt) => {
                self.storage
                    .db
                    .add_kel_finalized_event(prt.clone(), &prt.event_message.data.get_prefix())?;
                bus.notify(&Notification::KeyEventAdded(prt.clone()))?;
                let non_trans_receipt =
                    self.respond_to_key_event(&prt.event_message, self.signer.clone())?;
                let prefix = &non_trans_receipt.body.prefix.clone();
                self.storage
                    .db
                    .add_receipt_nt(non_trans_receipt.clone(), prefix)?;
                bus.notify(&Notification::ReceiptAccepted)?;
                self.storage.add_mailbox_receipt(non_trans_receipt)
            }
            _ => Ok(()),
        }
    }
}

impl WitnessReceiptGenerator {
    pub fn new(signer: Arc<Signer>, db: Arc<SledEventDatabase>) -> Self {
        let storage = EventStorage::new(db);
        let prefix = BasicPrefix::Ed25519NT(signer.public_key());
        Self {
            prefix,
            signer,
            storage,
        }
    }

    fn respond_to_key_event(
        &self,
        event_message: &KeriEvent<KeyEvent>,
        signer: Arc<Signer>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = signer.sign(ser)?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message.clone())
            .build()?;

        let signature = SelfSigningPrefix::Ed25519Sha512(signature);
        let nontrans = Nontransferable::Couplet(vec![(self.prefix.clone(), signature)]);

        let signed_rcp = SignedNontransferableReceipt::new(&rcp, vec![nontrans]);

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
    pub fn new(
        signer: Arc<Signer>,
        event_path: &Path,
        oobi_path: &Path,
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, Error> {
        use keri::{database::escrow::EscrowDb, processor::notification::JustNotification};
        let mut events_path = PathBuf::new();
        events_path.push(event_path);
        let mut escrow_path = events_path.clone();

        events_path.push("events");
        escrow_path.push("escrow");

        let prefix = BasicPrefix::Ed25519NT(signer.public_key());
        let db = Arc::new(SledEventDatabase::new(events_path.as_path())?);
        let escrow_db = Arc::new(EscrowDb::new(escrow_path.as_path())?);
        let mut witness_processor = WitnessProcessor::new(db.clone(), escrow_db, escrow_config);
        let event_storage = EventStorage::new(db.clone());

        let receipt_generator = Arc::new(WitnessReceiptGenerator::new(signer.clone(), db));
        witness_processor.register_observer(
            receipt_generator.clone(),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::PartiallyWitnessed,
            ],
        )?;
        Ok(Self {
            prefix,
            processor: witness_processor,
            signer,
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
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, Error> {
        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );
        let prefix = BasicPrefix::Ed25519NT(signer.public_key());
        let witness = Witness::new(signer.clone(), event_db_path, oobi_db_path, escrow_config)?;
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
            prefix,
            SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.serialize()?)?),
        );
        witness.oobi_manager.save_oobi(&signed_reply)?;
        Ok(witness)
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(self.oobi_manager.get_loc_scheme(eid)?.map(|oobis_to_sign| {
            oobis_to_sign
                .iter()
                .map(|oobi_to_sing| {
                    let signature = self.signer.sign(oobi_to_sing.serialize().unwrap()).unwrap();
                    SignedReply::new_nontrans(
                        oobi_to_sing.clone(),
                        self.prefix.clone(),
                        SelfSigningPrefix::Ed25519Sha512(signature),
                    )
                })
                .collect()
        }))
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

        let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(rpy.serialize()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn process_notice(&self, notice: Notice) -> Result<(), Error> {
        match self.processor.process_notice(&notice) {
            Err(Error::MissingDelegatorSealError(id)) => {
                if let Notice::Event(delegated_event) = notice {
                    self.event_storage
                        .add_mailbox_delegate(&id, delegated_event)
                } else {
                    Ok(())
                }
            }
            whatever => whatever,
        }
    }

    pub fn process_exchange(
        &self,
        exn: keri::mailbox::exchange::SignedExchange,
    ) -> Result<(), ActorError> {
        process_signed_exn(exn, &self.event_storage)?;
        Ok(())
    }

    pub fn process_reply(&self, rpy: SignedReply) -> Result<(), ActorError> {
        process_reply(
            rpy,
            &self.oobi_manager,
            &self.processor,
            &self.event_storage,
        )?;
        Ok(())
    }

    pub fn process_query(
        &self,
        qry: keri::query::query_event::SignedQuery,
    ) -> Result<Option<PossibleResponse>, ActorError> {
        let response = process_signed_query(qry, &self.event_storage)?;

        match response {
            ReplyType::Ksn(ksn) => {
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    SelfAddressing::Blake3_256,
                    SerializationFormats::JSON,
                )?;

                let signature =
                    SelfSigningPrefix::Ed25519Sha512(self.signer.sign(rpy.serialize()?)?);
                let reply = SignedReply::new_nontrans(rpy, self.prefix.clone(), signature);
                Ok(Some(PossibleResponse::Ksn(reply)))
            }
            ReplyType::Kel(msgs) => Ok(Some(PossibleResponse::Kel(msgs))),
            ReplyType::Mbx(mailbox_response) => Ok(Some(PossibleResponse::Mbx(mailbox_response))),
        }
    }

    pub fn parse_and_process_notices(&self, input_stream: &[u8]) -> Result<(), Error> {
        parse_notice_stream(input_stream)?
            .into_iter()
            .try_for_each(|notice| self.process_notice(notice))
    }

    pub fn parse_and_process_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<PossibleResponse>, ActorError> {
        parse_query_stream(input_stream)?
            .into_iter()
            .map(|qry| self.process_query(qry))
            .filter_map(Result::transpose)
            .collect()
    }

    pub fn parse_and_process_replies(&self, input_stream: &[u8]) -> Result<(), ActorError> {
        for reply in parse_reply_stream(input_stream)? {
            self.process_reply(reply)?;
        }
        Ok(())
    }

    pub fn parse_and_process_exchanges(&self, input_stream: &[u8]) -> Result<(), ActorError> {
        for exchange in parse_exchange_stream(input_stream)? {
            self.process_exchange(exchange)?;
        }
        Ok(())
    }

    pub fn get_mailbox_messages(&self, id: &IdentifierPrefix) -> Result<MailboxResponse, Error> {
        self.event_storage.get_mailbox_messages(QueryArgsMbx {
            pre: IdentifierPrefix::Basic(self.prefix.clone()),
            i: id.clone(),
            src: IdentifierPrefix::Basic(self.prefix.clone()),
            topics: QueryTopics {
                credential: 0,
                receipt: 0,
                replay: 0,
                multisig: 0,
                delegate: 0,
                reply: 0,
            },
        })
    }
}
