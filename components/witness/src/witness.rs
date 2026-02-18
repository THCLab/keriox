use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use keri_core::{
    actor::{
        error::ActorError, parse_exchange_stream, parse_notice_stream, parse_query_stream,
        parse_reply_stream, possible_response::PossibleResponse, prelude::*, process_reply,
        process_signed_exn, process_signed_query,
    },
    database::{
        redb::{RedbDatabase, RedbError},
        EventDatabase,
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
    oobi::LocationScheme,
    oobi_manager::OobiManager,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::notification::{Notification, NotificationBus, Notifier},
    query::{
        mailbox::{QueryArgsMbx, QueryTopics},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
};
use serde::{Deserialize, Serialize};
use teliox::{
    database::{redb::RedbTelDatabase, EscrowDatabase, TelEventDatabase},
    event::{parse_tel_query_stream, verifiable_event::VerifiableEvent},
    processor::{escrow::default_escrow_bus, storage::TelEventStorage, TelReplyType},
    tel::Tel,
};
use thiserror::Error;
use url::Url;

use crate::witness_processor::{WitnessEscrowConfig, WitnessProcessor};

pub struct WitnessReceiptGenerator {
    pub prefix: BasicPrefix,
    pub signer: Arc<Signer>,
    pub storage: EventStorage<RedbDatabase>,
}

impl Notifier for WitnessReceiptGenerator {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(event) => {
                let non_trans_receipt =
                    self.respond_to_key_event(&event.event_message, self.signer.clone())?;
                let prefix = &event.event_message.data.get_prefix(); //&non_trans_receipt.body.event.prefix.clone();
                self.storage
                    .events_db
                    .add_receipt_nt(non_trans_receipt.clone(), prefix)?;
                bus.notify(&Notification::ReceiptAccepted)?;
                self.storage.add_mailbox_receipt(non_trans_receipt)?;
                Ok(())
            }
            Notification::PartiallyWitnessed(prt) => {
                self.storage
                    .events_db
                    .add_kel_finalized_event(prt.clone(), &prt.event_message.data.get_prefix())?;
                bus.notify(&Notification::KeyEventAdded(prt.clone()))?;
                let non_trans_receipt =
                    self.respond_to_key_event(&prt.event_message, self.signer.clone())?;
                let prefix = &non_trans_receipt.body.prefix.clone();
                self.storage
                    .events_db
                    .add_receipt_nt(non_trans_receipt.clone(), prefix)?;
                bus.notify(&Notification::ReceiptAccepted)?;
                self.storage.add_mailbox_receipt(non_trans_receipt)
            }
            _ => Ok(()),
        }
    }
}

impl WitnessReceiptGenerator {
    pub fn new(signer: Arc<Signer>, events_db: Arc<RedbDatabase>) -> Self {
        let storage = EventStorage::new_redb(events_db.clone());
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
        let ser = event_message.encode()?;
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

#[derive(Error, Debug, Serialize, Deserialize)]
pub enum WitnessError {
    #[error(transparent)]
    KeriError(#[from] keri_core::error::Error),

    #[error(transparent)]
    TelError(#[from] teliox::error::Error),

    #[error("Db error: {0}")]
    DatabaseError(String),

    #[error("Signing error")]
    SigningError,
}

impl From<RedbError> for WitnessError {
    fn from(err: RedbError) -> Self {
        WitnessError::DatabaseError(err.to_string())
    }
}

pub struct Witness {
    pub address: Url,
    pub prefix: BasicPrefix,
    pub processor: WitnessProcessor,
    pub event_storage: Arc<EventStorage<RedbDatabase>>,
    pub oobi_manager: OobiManager,
    pub signer: Arc<Signer>,
    pub receipt_generator: Arc<WitnessReceiptGenerator>,
    pub tel: Arc<Tel<RedbTelDatabase, RedbDatabase>>,
}

impl Witness {
    pub fn new(
        address: Url,
        signer: Arc<Signer>,
        event_path: &Path,
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, WitnessError> {
        use keri_core::processor::notification::JustNotification;
        let mut events_path = PathBuf::new();
        events_path.push(event_path);
        let mut escrow_path = events_path.clone();
        let mut tel_path = events_path.clone();
        let mut events_database_path = events_path.clone();

        events_path.push("events");
        escrow_path.push("escrow");

        let prefix = BasicPrefix::Ed25519NT(signer.public_key());

        events_database_path.push("events_database");

        let events_db =
            Arc::new(RedbDatabase::new(&events_database_path).map_err(|_| Error::DbError)?);
        let mut witness_processor = WitnessProcessor::new(events_db.clone(), escrow_config);
        let event_storage = Arc::new(EventStorage::new_redb(events_db.clone()));

        let receipt_generator = Arc::new(WitnessReceiptGenerator::new(
            signer.clone(),
            events_db.clone(),
        ));
        witness_processor.register_observer(
            receipt_generator.clone(),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::PartiallyWitnessed,
            ],
        )?;

        // Initiate tel and it's escrows
        let tel_events_db = {
            tel_path.push("tel");
            tel_path.push("events");
            Arc::new(RedbTelDatabase::new(&tel_path).unwrap())
        };

        let tel_escrow_db = {
            let mut tel_path = events_path.clone();
            tel_path.push("tel");
            tel_path.push("escrow");
            EscrowDatabase::new(&tel_path)
                .map_err(|e| WitnessError::DatabaseError(e.to_string()))?
        };
        let (tel_bus, _missing_issuer, _out_of_order, _missing_registy) =
            default_escrow_bus(tel_events_db.clone(), event_storage.clone(), tel_escrow_db)
                .unwrap();

        let tel = Arc::new(Tel::new(
            Arc::new(TelEventStorage::new(tel_events_db.clone())),
            event_storage.clone(),
            Some(tel_bus),
        ));

        Ok(Self {
            address,
            prefix,
            processor: witness_processor,
            signer,
            event_storage,
            receipt_generator,
            oobi_manager: OobiManager::new(events_db.clone()),
            tel,
        })
    }

    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        priv_key: Option<String>,
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, WitnessError> {
        let signer = Arc::new(
            priv_key
                .map(|key| Signer::new_with_seed(&key.parse()?))
                .unwrap_or_else(|| Ok(Signer::new()))?,
        );
        let prefix = BasicPrefix::Ed25519NT(signer.public_key());
        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(prefix.clone()),
            public_address.scheme().parse().unwrap(),
            public_address.clone(),
        );
        let witness = Witness::new(public_address, signer.clone(), event_db_path, escrow_config)?;
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            prefix,
            SelfSigningPrefix::Ed25519Sha512(
                signer
                    .sign(reply.encode()?)
                    .map_err(|_e| WitnessError::SigningError)?,
            ),
        );
        witness.oobi_manager.save_oobi(&signed_reply)?;
        Ok(witness)
    }

    pub fn oobi(&self) -> LocationScheme {
        LocationScheme::new(
            IdentifierPrefix::Basic(self.prefix.clone()),
            self.address.scheme().parse().unwrap(),
            self.address.clone(),
        )
    }

    pub fn get_loc_scheme_for_id(&self, eid: &IdentifierPrefix) -> Result<Vec<SignedReply>, Error> {
        let oobis_to_sign = self.oobi_manager.get_loc_scheme(eid)?;
        oobis_to_sign
            .iter()
            .map(|oobi_to_sing| {
                let signature = self.signer.sign(oobi_to_sing.encode().unwrap()).unwrap();
                Ok(SignedReply::new_nontrans(
                    oobi_to_sing.clone(),
                    self.prefix.clone(),
                    SelfSigningPrefix::Ed25519Sha512(signature),
                ))
            })
            .collect()
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
            HashFunctionCode::Blake3_256,
            SerializationFormats::JSON,
        );

        let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(rpy.encode()?)?);
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
        exn: keri_core::mailbox::exchange::SignedExchange,
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
        qry: keri_core::query::query_event::SignedQueryMessage,
    ) -> Result<Option<PossibleResponse>, ActorError> {
        println!("Processing query: {:?}", qry);
        let response = process_signed_query(qry, &self.event_storage)?;

        match response {
            ReplyType::Ksn(ksn) => {
                let rpy = ReplyEvent::new_reply(
                    ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                    HashFunctionCode::Blake3_256,
                    SerializationFormats::JSON,
                );

                let signature = SelfSigningPrefix::Ed25519Sha512(self.signer.sign(rpy.encode()?)?);
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

    pub fn parse_and_process_tel_queries(
        &self,
        input_stream: &[u8],
    ) -> Result<Vec<TelReplyType>, ActorError> {
        Ok(parse_tel_query_stream(input_stream)
            .unwrap()
            .into_iter()
            .map(|qry| self.tel.processor.process_signed_query(qry))
            .collect::<Result<Vec<_>, _>>()
            .unwrap())
    }

    pub fn parse_and_process_tel_events(&self, input_stream: &[u8]) -> Result<(), ActorError> {
        VerifiableEvent::parse(input_stream)
            .unwrap()
            .into_iter()
            .map(|tel_event| self.tel.processor.process(tel_event))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        Ok(())
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
        self.event_storage.get_mailbox_messages(&QueryArgsMbx {
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
