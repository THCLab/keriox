#[cfg(feature = "query")]
use crate::event_message::keri_version::KeriVersion;
use std::convert::TryFrom;

use serde::{Deserialize, Serialize};

use crate::event_message::cesr_adapter::parse_cesr_stream_many;
#[cfg(feature = "oobi-manager")]
use crate::oobi_manager::{storage::OobiStorageBackend, OobiManager};
#[cfg(feature = "query")]
use crate::{
    database::EventDatabase,
    event_message::{signature::Signature, signed_event_message::Op},
    processor::event_storage::EventStorage,
    query::{
        key_state_notice::KeyStateNotice,
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
    mailbox::exchange::{Exchange, ExchangeMessage, ForwardTopic, SignedExchange},
    query::mailbox::MailboxRoute,
};
pub use cesrox::cesr_proof::MaterialPath;

pub mod error;
pub mod event_generator;

#[cfg(feature = "query")]
pub mod possible_response;
#[cfg(all(feature = "mailbox", feature = "oobi-manager"))]
pub mod simple_controller;

pub fn parse_event_stream(stream: &[u8]) -> Result<Vec<Message>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages.into_iter().map(Message::try_from).collect()
}

pub fn parse_notice_stream(stream: &[u8]) -> Result<Vec<Notice>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages.into_iter().map(Notice::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi-manager"))]
pub fn parse_op_stream(stream: &[u8]) -> Result<Vec<Op>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages.into_iter().map(Op::try_from).collect()
}

#[cfg(any(feature = "query", feature = "oobi-manager"))]
pub fn parse_query_stream(stream: &[u8]) -> Result<Vec<SignedQueryMessage>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages
        .into_iter()
        .map(SignedQueryMessage::try_from)
        .collect()
}

#[cfg(feature = "query")]
pub fn parse_reply_stream(stream: &[u8]) -> Result<Vec<SignedReply>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages.into_iter().map(SignedReply::try_from).collect()
}

#[cfg(feature = "mailbox")]
pub fn parse_exchange_stream(stream: &[u8]) -> Result<Vec<SignedExchange>, ParseError> {
    let messages = parse_cesr_stream_many(stream)?;
    messages.into_iter().map(SignedExchange::try_from).collect()
}

pub fn process_notice<P: Processor>(msg: Notice, processor: &P) -> Result<(), Error> {
    processor.process_notice(&msg)
}

#[cfg(feature = "query")]
pub fn process_reply<P: Processor, #[cfg(feature = "oobi-manager")] S: OobiStorageBackend>(
    sr: SignedReply,
    #[cfg(feature = "oobi-manager")] oobi_manager: &OobiManager<S>,
    processor: &P,
    event_storage: &EventStorage<P::Database>,
) -> Result<(), Error> {
    match sr.reply.get_route() {
        #[cfg(feature = "oobi-manager")]
        ReplyRoute::LocScheme(_) | ReplyRoute::EndRoleAdd(_) | ReplyRoute::EndRoleCut(_) => {
            process_signed_oobi(&sr, oobi_manager, event_storage)
        }
        // Without an OOBI manager there is nowhere to keep them.
        #[cfg(all(feature = "oobi", not(feature = "oobi-manager")))]
        ReplyRoute::LocScheme(_) | ReplyRoute::EndRoleAdd(_) | ReplyRoute::EndRoleCut(_) => Err(
            Error::SemanticError("OOBI replies need the oobi-manager feature".into()),
        ),
        ReplyRoute::Ksn(_, _) => processor.process_op_reply(&sr),
        // The KERI specification defines these OOBI replies but not what a
        // node does on receiving one.
        #[cfg(feature = "oobi")]
        route @ (ReplyRoute::OobiProcess(_)
        | ReplyRoute::OobiUrls(..)
        | ReplyRoute::OobiEndpoint(..)) => Err(Error::UnsupportedRoute(
            serde_json::to_value(&route)
                .ok()
                .and_then(|v| v["r"].as_str().map(str::to_string))
                .unwrap_or_default(),
        )),
    }
}

#[cfg(feature = "oobi-manager")]
pub fn process_signed_oobi<D: EventDatabase + 'static, S: OobiStorageBackend>(
    signed_oobi: &SignedReply,
    oobi_manager: &OobiManager<S>,
    event_storage: &EventStorage<D>,
) -> Result<(), Error> {
    use crate::processor::validator::EventValidator;

    let validator = EventValidator::new(event_storage.events_db.clone());
    event_storage.refuse_abandoned_signer(signed_oobi.signature.get_signer().as_ref())?;
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
    // The sender must sign the exchange (signatures MUST be attached to the
    // message body); an exchange with none reaches no mailbox.
    if exn.signature.is_empty() {
        return Err(Error::MissingSignatures);
    }
    // The KERI specification: `i` names the sender of an exchange.
    if !exn
        .signature
        .iter()
        .any(|signature| signature.get_signer().as_ref() == Some(&exn_message.data.sender))
    {
        return Err(Error::SemanticError(
            "the exchange is not signed by its sender i".into(),
        ));
    }
    for signature in &exn.signature {
        storage.refuse_abandoned_signer(signature.get_signer().as_ref())?;
    }
    let verification_result =
        exn.signature
            .iter()
            .try_fold(true, |acc, signature| -> Result<bool, Error> {
                Ok(acc && signature.verify(&exn_message.encode()?, storage)?)
            });
    if verification_result? {
        process_exn(exn_message, &exn.nested, storage)
    } else {
        Err(Error::SignatureVerificationError)
    }
}

#[cfg(feature = "mailbox")]
fn process_exn<D: EventDatabase>(
    exn: &ExchangeMessage,
    nested: &[Message],
    storage: &EventStorage<D>,
) -> Result<(), Error> {
    let exchange = &exn.data.content.data;
    let (recipient, topic) = match exchange {
        Exchange::Fwd { args, .. } => (&args.recipient_id, &args.topic),
        Exchange::Other { route, .. } => return Err(Error::UnsupportedRoute(route.clone())),
    };
    // `ri` names the recipient of the exchange, the AID whose mailbox a
    // forward is for.
    if recipient != &exn.data.recipient {
        return Err(Error::SemanticError(format!(
            "the forward is for {recipient}, the exchange names {} as its recipient",
            exn.data.recipient
        )));
    }
    // The one message forwarded, with its own signatures, receipts and
    // seals; the mailbox keeps key events.
    let forwarded = match nested {
        [Message::Notice(Notice::Event(event))] => event,
        [_] => {
            return Err(Error::SemanticError(
                "a mailbox keeps forwarded key events only".into(),
            ))
        }
        _ => {
            return Err(Error::SemanticError(format!(
                "a forward carries one message, this one {}",
                nested.len()
            )))
        }
    };
    if !exchange.forwards(&forwarded.event_message.encode()?) {
        return Err(Error::SemanticError(
            "the forwarded message is not the one a.evt names".into(),
        ));
    }
    match topic {
        ForwardTopic::Multisig => {
            storage.add_mailbox_multisig(recipient, forwarded.clone())?;
        }
        ForwardTopic::Delegate => {
            storage.add_mailbox_delegate(recipient, forwarded.clone())?;
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
            Ok(process_query(
                kqry.query.get_route(),
                KeriVersion::of(&kqry.query.serialization_info),
                storage,
            )?)
        }
        #[cfg(feature = "mailbox")]
        SignedQueryMessage::MailboxQuery(mqry) => {
            let signature = mqry.signature.clone();
            tracing::trace!(?signature, "MailboxQuery signature");
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
/// Answers a query; a key state notice is written in `version`, the version
/// of the query that asks for it.
pub fn process_query<D: EventDatabase>(
    qr: &QueryRoute,
    version: KeriVersion,
    storage: &EventStorage<D>,
) -> Result<ReplyType, QueryError> {
    match qr {
        QueryRoute::Ksn { args, .. } => {
            // return reply message with ksn inside
            let state = storage
                .get_state(&args.i)
                .ok_or_else(|| QueryError::UnknownId { id: args.i.clone() })?;
            let first_seen = storage.first_seen_number(&args.i)?.unwrap_or(state.sn);
            let ksn = KeyStateNotice::new_ksn(state, first_seen, version);
            Ok(ReplyType::Ksn(ksn))
        }
        QueryRoute::Logs {
            reply_route: _,
            args,
        } => {
            // `s` is where the replay starts: without a limit the log is
            // replayed from `s` to its end.
            let response = match (args.s, args.limit) {
                (None, _) => storage.get_kel_messages_with_receipts_all(&args.i)?,
                (Some(sn), None) => {
                    storage.get_kel_messages_with_receipts_range(&args.i, sn, u64::MAX - sn)?
                }
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
        // The KERI specification defines the query but not how a node finds
        // the OOBI it asks for.
        #[cfg(feature = "oobi")]
        QueryRoute::Oobi { .. } => Err(QueryError::Unsupported("/oobi".into())),
    }
}

#[cfg(feature = "mailbox")]
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

    /// A query route this node reads but does not answer.
    #[error("query route {0} is not served here")]
    Unsupported(String),
}

pub mod prelude {
    #[cfg(feature = "oobi-manager")]
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
