use std::convert::TryFrom;

#[cfg(feature = "oobi")]
use crate::oobi::OobiManager;
use crate::{
    error::Error,
    event_message::{
        exchange::{Exchange, ExchangeMessage, SignedExchange},
        serialization_info::SerializationFormats,
        signature::Signature,
        signed_event_message::{Message, Notice, Op, SignedEventMessage},
    },
    event_parsing::{
        message::{signed_event_stream, signed_notice_stream},
        path::MaterialPath,
    },
    prefix::IdentifierPrefix,
};
#[cfg(feature = "query")]
use crate::{
    processor::{event_storage::EventStorage, validator::EventValidator, Processor},
    query::{
        key_state_notice::KeyStateNotice,
        query_event::{Query, SignedQuery},
        reply_event::{ReplyRoute, SignedReply},
        ReplyType,
    },
};

pub mod simple_controller;

pub fn parse_event_stream(stream: &[u8]) -> Result<Vec<Message>, Error> {
    let (_rest, events) =
        signed_event_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    events.into_iter().map(Message::try_from).collect()
}

pub fn parse_notice_stream(stream: &[u8]) -> Result<Vec<Notice>, Error> {
    let (_rest, notices) =
        signed_notice_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    notices.into_iter().map(Notice::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_op_stream(stream: &[u8]) -> Result<Vec<Op>, Error> {
    use crate::event_parsing::message::signed_op_stream;

    let (_rest, ops) =
        signed_op_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    ops.into_iter().map(Op::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_query_stream(stream: &[u8]) -> Result<Vec<SignedQuery>, Error> {
    use crate::event_parsing::message::signed_op_stream;

    let (_rest, queries) =
        signed_op_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    queries.into_iter().map(SignedQuery::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_reply_stream(stream: &[u8]) -> Result<Vec<SignedReply>, Error> {
    use crate::event_parsing::message::signed_op_stream;

    let (_rest, replies) =
        signed_op_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    replies.into_iter().map(SignedReply::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi"))]
pub fn parse_exchange_stream(stream: &[u8]) -> Result<Vec<SignedExchange>, Error> {
    use crate::event_parsing::message::signed_op_stream;

    let (_rest, exchanges) =
        signed_op_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    exchanges.into_iter().map(SignedExchange::try_from).collect()
}

pub fn process_message<P: Processor>(
    msg: Message,
    oobi_manager: &OobiManager,
    processor: &P,
    event_storage: &EventStorage,
) -> Result<(), Error> {
    match msg {
        Message::Notice(notice) => process_notice(notice, processor)?,
        Message::Op(op) => {
            if let Op::Reply(reply) = op {
                process_reply(reply, oobi_manager, processor, event_storage)?;
            }
        }
    };
    Ok(())
}

pub fn process_notice<P: Processor>(msg: Notice, processor: &P) -> Result<(), Error> {
    processor.process_notice(&msg)
}

pub fn process_reply<P: Processor>(
    sr: SignedReply,
    oobi_manager: &OobiManager,
    processor: &P,
    event_storage: &EventStorage,
) -> Result<(), Error> {
    match sr.reply.get_route() {
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
    event_storage: &EventStorage,
) -> Result<(), Error> {
    let validator = EventValidator::new(event_storage.db.clone());
    // check signature
    validator.verify(&signed_oobi.reply.serialize()?, &signed_oobi.signature)?;
    // check digest
    signed_oobi.reply.check_digest()?;
    // save
    oobi_manager
        .process_oobi(signed_oobi)
        .map_err(|e| Error::SemanticError(e.to_string()))?;

    Ok(())
}

pub fn process_signed_exn(exn: SignedExchange, storage: &EventStorage) -> Result<(), Error> {
    let exn_message = &exn.exchange_message;
    let verification_result =
        exn.signature
            .iter()
            .try_fold(true, |acc, signature| -> Result<bool, Error> {
                Ok(acc && signature.verify(&exn_message.serialize()?, storage)?)
            });
    if verification_result? {
        process_exn(exn_message, exn.data_signature, storage)
    } else {
        Err(Error::SignatureVerificationError)
    }
}

fn process_exn(
    exn: &ExchangeMessage,
    attachemnt: (MaterialPath, Vec<Signature>),
    storage: &EventStorage,
) -> Result<(), Error> {
    let (receipient, to_forward) = match &exn.event.content {
        Exchange::Fwd { args, to_forward } => (&args.recipient_id, to_forward),
    };
    let sigs = attachemnt
        .1
        .into_iter()
        .map(|s| match s {
            Signature::Transferable(_sd, sigs) => sigs,
            Signature::NonTransferable(_, _) => todo!(),
        })
        .flatten()
        .collect();
    let signed_to_forward = SignedEventMessage {
        event_message: to_forward.clone(),
        signatures: sigs,
        witness_receipts: None,
        delegator_seal: None,
    };

    storage.add_mailbox_exchange(receipient, signed_to_forward)?;
    Ok(())
}

#[cfg(feature = "query")]
pub fn process_signed_query(
    qr: SignedQuery,
    storage: &EventStorage,
) -> Result<ReplyType, SignedQueryError> {
    let signatures = qr.signatures;
    // check signatures
    let signer_id = qr.signer.clone();
    match signer_id {
        IdentifierPrefix::Basic(id) if !id.is_transferable() => {
            // TODO: Define separate signature variant for non transferable identifiers.
            let sig = &signatures
                .get(0)
                .ok_or(SignedQueryError::InvalidSignature)?
                .signature;
            if !id.verify(&qr.query.serialize()?, sig)? {
                return Err(SignedQueryError::InvalidSignature);
            }
        }
        _ => {
            let key_config = storage
                .get_state(&signer_id)?
                .ok_or_else(|| SignedQueryError::UnknownSigner { id: signer_id })?
                .current;
            if !key_config.verify(&qr.query.serialize()?, &signatures)? {
                return Err(SignedQueryError::InvalidSignature);
            }
        }
    }

    // TODO check timestamps
    // unpack and check what's inside
    Ok(process_query(qr.query.get_query_data(), storage)?)
}

#[derive(Debug, thiserror::Error)]
pub enum SignedQueryError {
    #[error(transparent)]
    KeriError(#[from] crate::error::Error),

    #[error(transparent)]
    DbError(#[from] crate::database::DbError),

    #[error(transparent)]
    QueryError(#[from] QueryError),

    #[error("unknown signer with id {id:?}")]
    UnknownSigner { id: IdentifierPrefix },

    #[error("signature verification failed")]
    InvalidSignature,
}

#[cfg(feature = "query")]
fn process_query(qr: Query, storage: &EventStorage) -> Result<ReplyType, QueryError> {
    use crate::query::query_event::QueryRoute;

    match qr.route {
        QueryRoute::Log { args, .. } => Ok(ReplyType::Kel(
            storage
                .get_kel_messages_with_receipts(&args.i)?
                .ok_or_else(|| QueryError::UnknownId { id: args.i.clone() })?
                .into_iter()
                .map(Message::Notice)
                .collect(),
        )),
        QueryRoute::Ksn { args, .. } => {
            let i = args.i;
            // return reply message with ksn inside
            let state = storage
                .get_state(&i)?
                .ok_or_else(|| QueryError::UnknownId { id: i })?;
            let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
            Ok(ReplyType::Ksn(ksn))
        }
        QueryRoute::Mbx { args, .. } => {
            let mail = storage.get_mailbox_messages(args)?;
            Ok(ReplyType::Mbx(mail))
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QueryError {
    #[error(transparent)]
    KeriError(#[from] crate::error::Error),

    #[error(transparent)]
    DbError(#[from] crate::database::DbError),

    #[error("unknown identifier {id:?}")]
    UnknownId { id: IdentifierPrefix },
}

pub mod prelude {
    pub use crate::{
        actor::{
            process_message, process_notice, process_reply, process_signed_oobi,
            process_signed_query,
        },
        database::SledEventDatabase,
        event::SerializationFormats,
        event_message::signed_event_message::Message,
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
        query::ReplyType,
    };
}
