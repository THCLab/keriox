use std::sync::Arc;

use crate::{database::sled::SledEventDatabase, error::Error, event_message::signed_event_message::{SignedEventMessage, Message}, query::{reply_event::ReplyRoute, query_event::QueryRoute}};

use super::{validator::EventValidator, notification::{NotificationBus, Notification}};

pub struct EventProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
    publisher: NotificationBus,
}

impl EventProcessor {
    pub fn new(db: Arc<SledEventDatabase>, publisher: NotificationBus) -> Self {
        let validator = EventValidator::new(db.clone());
        Self {
            db,
            validator,
            publisher,
        }
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    /// Update database based on event validation result.
    pub fn process<F>(&self, message: Message, processing_strategy: F) -> Result<(), Error> 
    where F: Fn(Arc<SledEventDatabase>, &NotificationBus, SignedEventMessage) -> Result<(), Error> {
        match message {
            Message::Event(signed_event) => {
                processing_strategy(self.db.clone(), &self.publisher, signed_event)
            }
            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix;
                match self.validator.validate_witness_receipt(&rct) {
                    Ok(_) => {
                        self.db.add_receipt_nt(rct.to_owned(), id)?;
                        self.publisher.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) => self
                        .publisher
                        .notify(&Notification::ReceiptOutOfOrder(rct.clone())),
                    Err(e) => Err(e),
                }
            }
            Message::TransferableRct(vrc) => {
                match self.validator.validate_validator_receipt(&vrc) {
                    Ok(_) => {
                        self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix)?;
                        self.publisher.notify(&Notification::ReceiptAccepted)
                    }
                    Err(Error::MissingEvent) | Err(Error::EventOutOfOrderError) => self
                        .publisher
                        .notify(&Notification::TransReceiptOutOfOrder(vrc.clone())),
                    Err(e) => Err(e),
                }
            }
            #[cfg(feature = "query")]
            Message::Reply(rpy) => match rpy.reply.get_route() {
                ReplyRoute::Ksn(_, _) => match self.validator.process_signed_ksn_reply(&rpy) {
                    Ok(_) => {
                        self.db
                            .update_accepted_reply(rpy.clone(), &rpy.reply.get_prefix())?;
                        self.publisher.notify(&Notification::ReplyUpdated)
                    }
                    Err(Error::EventOutOfOrderError) => {
                        self.publisher.notify(&Notification::KsnOutOfOrder(rpy))
                    }
                    Err(anything) => Err(anything),
                },
                #[cfg(feature = "oobi")]
                ReplyRoute::EndRoleAdd(_)
                | ReplyRoute::EndRoleCut(_)
                | ReplyRoute::LocScheme(_) => {
                    // check signature
                    self.validator
                        .verify(&rpy.reply.serialize()?, &rpy.signature)?;
                    // check digest
                    rpy.reply.check_digest()?;
                    self.publisher.notify(&Notification::GotOobi(rpy))
                }
            },
            #[cfg(feature = "query")]
            Message::Query(qry) => match qry.query.event.content.data.route {
                QueryRoute::Log { args, .. } => {
                    let pref = args.i;
                    println!("Respond with {} key event log.", pref);
                    self.publisher.notify(&Notification::ReplayLog(pref))
                }
                QueryRoute::Ksn {
                    reply_route: _,
                    args,
                } => self.publisher.notify(&Notification::ReplyKsn(args.i)),
                QueryRoute::Mbx { args, .. } => {
                    self.publisher.notify(&Notification::GetMailbox(args))
                }
            },
        }
    }
}
