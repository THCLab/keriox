use crate::{error::Error, event_message::signed_event_message::Message, prefix::IdentifierPrefix};

use super::EventProcessor;

pub fn process_nt_receipts_escrow(processor: &EventProcessor) -> Result<(), Error> {
    if let Some(esc) = processor.db.get_all_escrow_nt_receipts() {
        esc.for_each(|sig_receipt| {
            match processor.validator.process_witness_receipt(&sig_receipt) {
                Ok(_) | Err(Error::SignatureVerificationError) => {
                    // remove from escrow
                    processor
                        .db
                        .remove_escrow_nt_receipt(&sig_receipt.body.event.prefix, &sig_receipt)
                        .unwrap();
                }
                Err(_e) => {} // keep in escrow,
            }
        })
    };

    Ok(())
}

pub fn process_partially_witnessed_events(processor: &EventProcessor) -> Result<(), Error> {
    if let Some(esc) = processor.db.get_all_partially_witnessed() {
        esc.for_each(|event| {
            match processor.process(Message::Event(event.signed_event_message.clone())) {
                Ok(_) | Err(Error::SignatureVerificationError) => {
                    // remove from escrow
                    processor
                        .db
                        .remove_partially_witnessed_event(
                            &event.signed_event_message.event_message.event.get_prefix(),
                            &event.signed_event_message,
                        )
                        .unwrap();
                }
                Err(_e) => {} // keep in escrow,
            }
        })
    };

    Ok(())
}

pub fn process_out_of_order_events(
    processor: &EventProcessor,
    id: &IdentifierPrefix,
) -> Result<(), Error> {
    if let Some(esc) = processor.db.get_out_of_order_events(id) {
        esc.for_each(|event| {
            match processor
                .validator
                .process_event(&event.signed_event_message.clone())
            {
                Ok(_) => {
                    // add to kel
                    processor
                        .db
                        .add_kel_finalized_event(event.signed_event_message.clone(), id)
                        .unwrap();
                    // remove from escrow
                    processor
                        .db
                        .remove_out_of_order_event(&id, &event.signed_event_message)
                        .unwrap();
                }
                Err(Error::SignatureVerificationError) => {
                    // remove from escrow
                    processor
                        .db
                        .remove_out_of_order_event(id, &event.signed_event_message)
                        .unwrap();
                }
                Err(_e) => {} // keep in escrow,
            }
        })
    };

    Ok(())
}

#[cfg(feature = "query")]
pub fn process_reply_escrow(processor: &EventProcessor) -> Result<(), Error> {
    use crate::query::QueryError;

    processor.db.get_all_escrowed_replys().map(|esc| {
        esc.for_each(|sig_rep| {
            match processor.process(Message::KeyStateNotice(sig_rep.clone())) {
                Ok(_)
                | Err(Error::SignatureVerificationError)
                | Err(Error::QueryError(QueryError::StaleRpy)) => {
                    // remove from escrow
                    processor
                        .db
                        .remove_escrowed_reply(&sig_rep.reply.event.get_prefix(), sig_rep)
                        .unwrap();
                }
                Err(_e) => {} // keep in escrow,
            }
        })
    });
    Ok(())
}
