use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

#[cfg(feature = "oobi")]
use crate::database::redb::RedbDatabase;
#[cfg(feature = "oobi")]
use crate::oobi::OobiManager;
#[cfg(feature = "query")]
use crate::{
    database::EventDatabase,
    event_message::signed_event_message::Op,
    processor::event_storage::EventStorage,
    query::{
        key_state_notice::KeyStateNotice,
        mailbox::MailboxRoute,
        query_event::QueryRoute,
        query_event::SignedQueryMessage,
        reply_event::{ReplyRoute, SignedReply},
        ReplyType,
    },
};
use crate::{
    error::Error,
    event_message::{
        cesr_adapter::ParseError,
        signed_event_message::{Message, Notice},
    },
    prefix::IdentifierPrefix,
    processor::Processor,
};
#[cfg(feature = "mailbox")]
use crate::{
    event_message::{signature::Signature, signed_event_message::SignedEventMessage},
    mailbox::exchange::{Exchange, ExchangeMessage, ForwardTopic, SignedExchange},
};
pub use cesrox::cesr_proof::MaterialPath;
use cesrox::parse_many;
#[cfg(feature = "query")]
use said::version::format::SerializationFormats;

pub mod error;
pub mod event_generator;
#[cfg(all(feature = "query", feature = "oobi", feature = "mailbox"))]
pub mod simple_controller;

pub fn parse_event_stream(stream: &[u8]) -> Result<Vec<Message>, ParseError> {
    let (_rest, events) = parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    events.into_iter().map(Message::try_from).collect()
}

pub fn parse_notice_stream(stream: &[u8]) -> Result<Vec<Notice>, ParseError> {
    let (_rest, notices) = parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    notices.into_iter().map(Notice::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_op_stream(stream: &[u8]) -> Result<Vec<Op>, ParseError> {
    let (_rest, ops) = parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    ops.into_iter().map(Op::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_query_stream(stream: &[u8]) -> Result<Vec<SignedQueryMessage>, ParseError> {
    let (_rest, queries) = parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    queries
        .into_iter()
        .map(SignedQueryMessage::try_from)
        .collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_reply_stream(stream: &[u8]) -> Result<Vec<SignedReply>, ParseError> {
    let (_rest, replies) = parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    replies.into_iter().map(SignedReply::try_from).collect()
}

#[cfg(feature = "mailbox")]
pub fn parse_exchange_stream(stream: &[u8]) -> Result<Vec<SignedExchange>, ParseError> {
    let (_rest, exchanges) =
        parse_many(stream).map_err(|e| ParseError::CesrError(e.to_string()))?;
    exchanges
        .into_iter()
        .map(SignedExchange::try_from)
        .collect()
}

pub fn process_notice<P: Processor>(msg: Notice, processor: &P) -> Result<(), Error> {
    processor.process_notice(&msg)
}

#[cfg(feature = "query")]
pub fn process_reply<P: Processor<Database = RedbDatabase>>(
    sr: SignedReply,
    #[cfg(feature = "oobi")] oobi_manager: &OobiManager,
    processor: &P,
    event_storage: &EventStorage<P::Database>,
) -> Result<(), Error> {
    match sr.reply.get_route() {
        #[cfg(feature = "oobi")]
        ReplyRoute::LocScheme(_) | ReplyRoute::EndRoleAdd(_) | ReplyRoute::EndRoleCut(_) => {
            process_signed_oobi(&sr, oobi_manager, event_storage)
        }
        ReplyRoute::Ksn(_, _) => processor.process_op_reply(&sr),
    }
}

#[cfg(feature = "oobi")]
pub fn process_signed_oobi(
    signed_oobi: &SignedReply,
    oobi_manager: &OobiManager,
    event_storage: &EventStorage<RedbDatabase>,
) -> Result<(), Error> {
    use crate::processor::validator::EventValidator;

    let validator = EventValidator::new(event_storage.events_db.clone());
    // check signature
    validator.verify(&signed_oobi.reply.encode()?, &signed_oobi.signature)?;
    // check digest
    signed_oobi.reply.check_digest()?;
    // save
    oobi_manager
        .process_oobi(signed_oobi)
        .map_err(|e| Error::SemanticError(e.to_string()))?;

    Ok(())
}

#[cfg(feature = "mailbox")]
pub fn process_signed_exn<D: EventDatabase>(
    exn: SignedExchange,
    storage: &EventStorage<D>,
) -> Result<(), Error> {
    let exn_message = &exn.exchange_message;
    let verification_result =
        exn.signature
            .iter()
            .try_fold(true, |acc, signature| -> Result<bool, Error> {
                Ok(acc && signature.verify(&exn_message.encode()?, storage)?)
            });
    if verification_result? {
        process_exn(exn_message, exn.data_signature, storage)
    } else {
        Err(Error::SignatureVerificationError)
    }
}

#[cfg(feature = "mailbox")]
fn process_exn<D: EventDatabase>(
    exn: &ExchangeMessage,
    attachment: (MaterialPath, Vec<Signature>),
    storage: &EventStorage<D>,
) -> Result<(), Error> {
    let (recipient, to_forward, topic) = match &exn.data.data {
        Exchange::Fwd { args, to_forward } => (&args.recipient_id, to_forward, &args.topic),
    };
    let (sigs, witness_receipts) = attachment.1.into_iter().fold(
        (vec![], vec![]),
        |(mut signatures, mut witness_receipts), s| {
            match s {
                Signature::Transferable(_sd, mut sigs) => signatures.append(&mut sigs),
                Signature::NonTransferable(receipts) => witness_receipts.push(receipts),
            }
            (signatures, witness_receipts)
        },
    );

    let signed_to_forward = SignedEventMessage {
        event_message: to_forward.clone(),
        signatures: sigs,
        witness_receipts: if witness_receipts.is_empty() {
            None
        } else {
            Some(witness_receipts)
        },
        delegator_seal: None,
    };

    match topic {
        ForwardTopic::Multisig => {
            storage.add_mailbox_multisig(recipient, signed_to_forward)?;
        }
        ForwardTopic::Delegate => {
            storage.add_mailbox_delegate(recipient, signed_to_forward)?;
        }
    };
    Ok(())
}

#[cfg(feature = "query")]
pub fn process_signed_query<D: EventDatabase>(
    qr: SignedQueryMessage,
    storage: &EventStorage<D>,
) -> Result<ReplyType, SignedQueryError> {
    let verify = |data: &[u8], signature: Signature| -> Result<_, SignedQueryError> {
        let ver_result = signature.verify(&data, storage)?;
        if !ver_result {
            Err(SignedQueryError::InvalidSignature)
        } else {
            Ok(())
        }
    };
    match qr {
        SignedQueryMessage::KelQuery(kqry) => {
            let signature = kqry.signature;
            let data = &kqry.query.encode().map_err(|_e| Error::VersionError)?;
            // check signatures
            verify(&data, signature)?;

            // TODO check timestamps
            // unpack and check what's inside
            Ok(process_query(kqry.query.get_route(), storage)?)
        }
        SignedQueryMessage::MailboxQuery(mqry) => {
            let signature = mqry.signature;
            let data = &mqry.query.encode().map_err(|_e| Error::VersionError)?;
            // check signatures
            verify(&data, signature)?;
            Ok(process_mailbox_query(&mqry.query.data.data, storage)?)
        }
    }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum SignedQueryError {
    #[error(transparent)]
    KeriError(#[from] crate::error::Error),

    #[error(transparent)]
    QueryError(#[from] QueryError),

    #[error("unknown signer with id {id:?}")]
    UnknownSigner { id: IdentifierPrefix },

    #[error("signature verification failed")]
    InvalidSignature,
}

#[cfg(feature = "query")]
pub fn process_query<D: EventDatabase>(
    qr: &QueryRoute,
    storage: &EventStorage<D>,
) -> Result<ReplyType, QueryError> {
    match qr {
        QueryRoute::Ksn { args, .. } => {
            // return reply message with ksn inside
            let state = storage
                .get_state(&args.i)
                .ok_or_else(|| QueryError::UnknownId { id: args.i.clone() })?;
            let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
            Ok(ReplyType::Ksn(ksn))
        }
        QueryRoute::Logs {
            reply_route: _,
            args,
        } => {
            let response = match (args.s, args.limit) {
                (None, _) => storage.get_kel_messages_with_receipts_all(&args.i)?,
                (Some(sn), None) => storage
                    .get_event_at_sn(&args.i, sn)
                    .map(|event| vec![Notice::Event(event.signed_event_message)]),
                (Some(sn), Some(limit)) => {
                    storage.get_kel_messages_with_receipts_range(&args.i, sn, limit)?
                }
            }
            .ok_or_else(|| QueryError::UnknownId { id: args.i.clone() })?
            .into_iter()
            .map(Message::Notice)
            .collect::<Vec<_>>();

            Ok(ReplyType::Kel(response))
        }
    }
}

#[cfg(feature = "query")]
pub fn process_mailbox_query<D: EventDatabase>(
    qr: &MailboxRoute,
    storage: &EventStorage<D>,
) -> Result<ReplyType, QueryError> {
    match qr {
        MailboxRoute::Mbx { args, .. } => {
            let mail = storage.get_mailbox_messages(args)?;
            Ok(ReplyType::Mbx(mail))
        }
    }
}

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum QueryError {
    #[error(transparent)]
    KeriError(#[from] crate::error::Error),

    #[error("unknown identifier {id:?}")]
    UnknownId { id: IdentifierPrefix },
}

pub mod prelude {
    #[cfg(feature = "oobi")]
    pub use crate::actor::process_signed_oobi;
    #[cfg(feature = "query")]
    pub use crate::actor::{process_reply, process_signed_query};
    #[cfg(feature = "query")]
    pub use crate::query::ReplyType;
    pub use crate::{
        actor::process_notice,
        event_message::signed_event_message::Message,
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
    };
    pub use said::version::{error::Error as VersionError, format::SerializationFormats};
    pub use said::{
        derivation::HashFunction, derivation::HashFunctionCode, SelfAddressingIdentifier,
    };
}
