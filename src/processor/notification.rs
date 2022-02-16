use std::collections::HashMap;

use crate::{
    error::Error,
    event_message::signed_event_message::{
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
    prefix::IdentifierPrefix,
    query::reply::SignedReply,
};

pub struct NotificationBus {
    observers: HashMap<JustNotification, Vec<Box<dyn Notifier>>>,
}

impl NotificationBus {
    pub fn new() -> Self {
        Self {
            observers: HashMap::new(),
        }
    }

    pub fn register_observer<N: Notifier + Clone + 'static>(
        &mut self,
        escrow: N,
        notification: Vec<JustNotification>,
    ) {
        notification.into_iter().for_each(|notification| {
            self.observers
                .entry(notification)
                .or_insert(vec![])
                .push(Box::new(escrow.clone()));
        });
    }

    pub fn notify(&self, notification: &Notification) -> Result<(), Error> {
        self.observers.get(&notification.into()).map(|obs| {
            obs.iter().for_each(|esc| {
                esc.notify(notification, self).unwrap();
            })
        });
        Ok(())
    }
}

pub trait Notifier {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error>;
}

#[derive(PartialEq)]
pub enum Notification {
    KeyEventAdded(IdentifierPrefix),
    OutOfOrder(SignedEventMessage),
    PartiallySigned(SignedEventMessage),
    PartiallyWitnessed(SignedEventMessage),
    ReceiptAccepted,
    ReceiptEscrowed,
    ReceiptOutOfOrder(SignedNontransferableReceipt),
    TransReceiptOutOfOrder(SignedTransferableReceipt),
    #[cfg(feature = "query")]
    ReplyOutOfOrder(SignedReply),
    #[cfg(feature = "query")]
    ReplyUpdated,
}

#[derive(PartialEq, Hash, Eq)]
pub enum JustNotification {
    KeyEventAdded,
    OutOfOrder,
    PartiallySigned,
    PartiallyWitnessed,
    ReceiptAccepted,
    ReceiptEscrowed,
    ReceiptOutOfOrder,
    TransReceiptOutOfOrder,
    #[cfg(feature = "query")]
    ReplyOutOfOrder,
    #[cfg(feature = "query")]
    ReplyUpdated,
}

impl Into<JustNotification> for &Notification {
    fn into(self) -> JustNotification {
        match self {
            Notification::KeyEventAdded(_) => JustNotification::KeyEventAdded,
            Notification::OutOfOrder(_) => JustNotification::OutOfOrder,
            Notification::PartiallySigned(_) => JustNotification::PartiallySigned,
            Notification::PartiallyWitnessed(_) => JustNotification::PartiallyWitnessed,
            Notification::ReceiptAccepted => JustNotification::ReceiptAccepted,
            Notification::ReceiptEscrowed => JustNotification::ReceiptEscrowed,
            Notification::ReceiptOutOfOrder(_) => JustNotification::ReceiptOutOfOrder,
            Notification::TransReceiptOutOfOrder(_) => JustNotification::TransReceiptOutOfOrder,
            #[cfg(feature = "query")]
            Notification::ReplyOutOfOrder(_) => JustNotification::ReplyOutOfOrder,
            #[cfg(feature = "query")]
            Notification::ReplyUpdated => JustNotification::ReplyUpdated,
        }
    }
}
