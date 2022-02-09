use super::EventProcessor;
use crate::{
    error::Error,
    event_message::signed_event_message::{
        Message, SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
    prefix::IdentifierPrefix,
};

#[cfg(feature = "query")]
use crate::query::reply::SignedReply;

pub trait Escrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error>;
}

pub enum Notification {
    KelUpdated(IdentifierPrefix),
    ReceiptAccepted(SignedNontransferableReceipt),
    ReceiptEscrowed,
    NontransReceiptOutOfOrder(SignedNontransferableReceipt),
    TransReceiptOutOfOrder(SignedTransferableReceipt),
    OutOfOrder(SignedEventMessage),
    PartiallyWitnessed(SignedEventMessage),
    #[cfg(feature = "query")]
    ReplyOutOfOrder(SignedReply),
    #[cfg(feature = "query")]
    ReplyUpdated,
}

#[derive(Default)]
pub struct OutOfOrderEscrow;
// TODO fix error handling
impl OutOfOrderEscrow {
    pub fn process_out_of_order_events(
        processor: &EventProcessor,
        id: &IdentifierPrefix,
    ) -> Result<(), Error> {
        if let Some(mut esc) = processor.db.get_out_of_order_events(id) {
            esc.try_for_each(|event| {
                match processor
                    .validator
                    .process_event(&event.signed_event_message.clone())
                {
                    Ok(_) => {
                        // add to kel
                        processor
                            .db
                            .add_kel_finalized_event(event.signed_event_message.clone(), id)
                            .expect("Database problem");
                        // remove from escrow
                        processor
                            .db
                            .remove_out_of_order_event(&id, &event.signed_event_message)
                            .expect("Database problem");
                        processor
                            .notify(&Notification::KelUpdated(
                                event.signed_event_message.event_message.event.get_prefix(),
                            ))
                            .expect("Notification problem");
                        // stop processing the escrow if kel was updated. It needs to start again.
                        None
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        processor
                            .db
                            .remove_out_of_order_event(id, &event.signed_event_message)
                            .expect("Database problem");
                        Some(())
                    }
                    Err(_e) => Some(()), // keep in escrow,
                }
            });
        };

        Ok(())
    }
}
impl Escrow for OutOfOrderEscrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error> {
        match notification {
            Notification::KelUpdated(id) => Self::process_out_of_order_events(processor, &id),
            Notification::OutOfOrder(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                processor
                    .db
                    .add_out_of_order_event(signed_event.clone(), id)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Default)]
pub struct PartiallyWitnessedEscrow;
// TODO fix error handling
impl PartiallyWitnessedEscrow {
    pub fn process_partially_witnessed_events(processor: &EventProcessor) -> Result<(), Error> {
        if let Some(mut esc) = processor.db.get_all_partially_witnessed() {
            esc.try_for_each(|event| {
                let id = event.signed_event_message.event_message.event.get_prefix();
                match processor
                    .validator
                    .process_event(&event.signed_event_message.clone())
                {
                    Ok(_) => {
                        // add to kel
                        processor
                            .db
                            .add_kel_finalized_event(event.signed_event_message.clone(), &id)
                            .unwrap();
                        // remove from escrow
                        processor
                            .db
                            .remove_partially_witnessed_event(&id, &event.signed_event_message)
                            .expect("Database problem");
                        processor
                            .notify(&Notification::KelUpdated(
                                event.signed_event_message.event_message.event.get_prefix(),
                            ))
                            .expect("Notification problem");
                        // stop processing the escrow if kel was updated. It needs to start again.
                        return None;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        processor
                            .db
                            .remove_partially_witnessed_event(&id, &event.signed_event_message)
                            .expect("Database problem");
                        Some(())
                    }
                    Err(_e) => Some(()), // keep in escrow,
                }
            });
        };

        Ok(())
    }
}
impl Escrow for PartiallyWitnessedEscrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error> {
        match notification {
            Notification::ReceiptAccepted(_) | Notification::ReceiptEscrowed => {
                Self::process_partially_witnessed_events(processor)
            }
            Notification::PartiallyWitnessed(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                processor
                    .db
                    .add_partially_witnessed_event(signed_event.clone(), id)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Default)]
pub struct NontransReceiptsEscrow;
// TODO fix error handling
impl NontransReceiptsEscrow {
    pub fn process_nt_receipts_escrow(processor: &EventProcessor) -> Result<(), Error> {
        if let Some(mut esc) = processor.db.get_all_escrow_nt_receipts() {
            esc.try_for_each(|sig_receipt| {
                let id = sig_receipt.body.event.prefix.clone();
                match processor.validator.process_witness_receipt(&sig_receipt) {
                    Ok(_) => {
                        // add to receipts
                        processor
                            .db
                            .add_receipt_nt(sig_receipt.clone(), &id)
                            .unwrap();
                        // remove from escrow
                        processor
                            .db
                            .remove_escrow_nt_receipt(&id, &sig_receipt)
                            .unwrap();
                        processor.notify(&Notification::ReceiptAccepted(sig_receipt))
                        // stop processing the escrow if kel was updated. It needs to start again.
                        // return Some(());
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        processor.db.remove_escrow_nt_receipt(&id, &sig_receipt)
                        // Some(())
                    }
                    Err(e) => Err(e), // keep in escrow,
                }
            })?;
        };

        Ok(())
    }
}
impl Escrow for NontransReceiptsEscrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error> {
        match notification {
            Notification::KelUpdated(_id) => Self::process_nt_receipts_escrow(processor),
            Notification::NontransReceiptOutOfOrder(receipt) => {
                let id = &receipt.body.event.prefix;
                processor.db.add_escrow_nt_receipt(receipt.clone(), id)?;
                processor.notify(&Notification::ReceiptEscrowed)
            }
            _ => Ok(()),
        }
    }
}

#[derive(Default)]
pub struct TransReceiptsEscrow;
impl Escrow for TransReceiptsEscrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error> {
        match notification {
            // Notification::KelUpdated(id) => process_t_receipts_escrow(processor),
            Notification::TransReceiptOutOfOrder(receipt) => {
                let id = &receipt.body.event.prefix;
                processor.db.add_escrow_t_receipt(receipt.to_owned(), id)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(feature = "query")]
pub struct ReplyEscrow;
impl ReplyEscrow {
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
}

impl Escrow for ReplyEscrow {
    fn notify(&self, notification: &Notification, processor: &EventProcessor) -> Result<(), Error> {
        match notification {
            Notification::ReplyOutOfOrder(rpy) => {
                let id = rpy.reply.event.get_prefix();
                processor.db.add_escrowed_reply(rpy.clone(), &id)
            },
            &Notification::KelUpdated(_) => ReplyEscrow::process_reply_escrow(processor),
            _ => {Ok(())}
        }
        
    }
} 
