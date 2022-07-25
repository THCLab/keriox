use std::convert::TryFrom;

#[cfg(feature = "oobi")]
use crate::oobi::OobiManager;
use crate::{
    error::Error,
    event_message::{
        serialization_info::SerializationFormats,
        signed_event_message::{Message, Notice, Op},
    },
    event_parsing::message::{signed_event_stream, signed_notice_stream},
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
#[cfg(feature = "query")]
pub fn process_signed_query(qr: SignedQuery, storage: &EventStorage) -> Result<ReplyType, Error> {
    let signatures = qr.signatures;
    // check signatures
    let kc = storage
        .get_state(&qr.signer)?
        .ok_or_else(|| Error::SemanticError("No signer identifier in db".into()))?
        .current;

    if kc.verify(&qr.query.serialize()?, &signatures)? {
        // TODO check timestamps
        // unpack and check what's inside
        process_query(qr.query.get_query_data(), storage)
    } else {
        Err(Error::SignatureVerificationError)
    }
}

#[cfg(feature = "query")]
fn process_query(qr: Query, storage: &EventStorage) -> Result<ReplyType, Error> {
    use crate::query::query_event::QueryRoute;

    match qr.route {
        QueryRoute::Log { args, .. } => Ok(ReplyType::Kel(
            storage
                .get_kel_messages_with_receipts(&args.i)?
                .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?
                .into_iter()
                .map(Message::Notice)
                .collect(),
        )),
        QueryRoute::Ksn { args, .. } => {
            let i = args.i;
            // return reply message with ksn inside
            let state = storage
                .get_state(&i)?
                .ok_or_else(|| Error::SemanticError("No id in database".into()))?;
            let ksn = KeyStateNotice::new_ksn(state, SerializationFormats::JSON);
            Ok(ReplyType::Ksn(ksn))
        }
        QueryRoute::Mbx { args, .. } => {
            let mail = storage
                .get_mailbox_messages(args)?
                .into_iter()
                .map(Message::Notice)
                .collect();
            Ok(ReplyType::Mbx(mail))
        }
    }
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
