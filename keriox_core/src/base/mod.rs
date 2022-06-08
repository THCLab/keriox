use std::convert::TryFrom;

use crate::{
    error::Error,
    event_message::{serialization_info::SerializationFormats, signed_event_message::Message},
    event_parsing::message::signed_event_stream,
    oobi::OobiManager,
    processor::{event_storage::EventStorage, validator::EventValidator, Processor},
    query::{
        key_state_notice::KeyStateNotice,
        query_event::{QueryData, SignedQuery},
        reply_event::{ReplyRoute, SignedReply},
        ReplyType,
    },
};

pub fn parse_event_stream(stream: &[u8]) -> Result<Vec<Message>, Error> {
    let (_rest, events) =
        signed_event_stream(stream).map_err(|e| Error::DeserializeError(e.to_string()))?;
    events
        .into_iter()
        .map(|event_data| Message::try_from(event_data))
        .collect::<Result<_, _>>()
}

/// Process key events and oobi events.
pub fn process_event<P: Processor>(
    msg: Message,
    oobi_manager: &OobiManager,
    processor: &P,
    event_storage: &EventStorage,
) -> Result<(), Error> {
    match msg.clone() {
        Message::Reply(sr) => match sr.reply.get_route() {
            ReplyRoute::LocScheme(_) | ReplyRoute::EndRoleAdd(_) | ReplyRoute::EndRoleCut(_) => {
                process_signed_oobi(sr, oobi_manager, event_storage)
            }
            ReplyRoute::Ksn(_, _) => processor.process(msg),
        },

        _ => processor.process(msg),
    }
}

pub fn process_signed_oobi(
    signed_oobi: SignedReply,
    oobi_manager: &OobiManager,
    event_storage: &EventStorage,
) -> Result<(), Error> {
    let validator = EventValidator::new(event_storage.db.clone());
    // check signature
    validator.verify(&signed_oobi.reply.serialize()?, &signed_oobi.signature)?;
    // check digest
    signed_oobi.reply.check_digest()?;
    // save
    oobi_manager.process_oobi(signed_oobi)
}

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

fn process_query(qr: QueryData, storage: &EventStorage) -> Result<ReplyType, Error> {
    use crate::query::query_event::QueryRoute;

    match qr.route {
        QueryRoute::Log { args, .. } => Ok(ReplyType::Kel(
            storage
                .get_kel_messages_with_receipts(&args.i)?
                .ok_or_else(|| Error::SemanticError("No identifier in db".into()))?,
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
            let mail = storage.get_mailbox_events(args)?;
            Ok(ReplyType::Mbx(mail))
        }
    }
}
