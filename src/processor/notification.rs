use std::collections::HashMap;

#[cfg(feature = "query")]
use crate::query::reply::SignedReply;
use crate::{
    error::Error,
    event_message::signed_event_message::{
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
};

#[derive(Default)]
pub struct NotificationBus {
    observers: HashMap<JustNotification, Vec<Box<dyn Notifier>>>,
}

impl NotificationBus {
    pub fn register_observer<N: Notifier + Clone + 'static>(
        &mut self,
        escrow: N,
        notification: Vec<JustNotification>,
    ) {
        notification.into_iter().for_each(|notification| {
            self.observers
                .entry(notification)
                .or_insert_with(Vec::new)
                .push(Box::new(escrow.clone()));
        });
    }

    pub fn notify(&self, notification: &Notification) -> Result<(), Error> {
        if let Some(obs) = self.observers.get(&notification.into()) {
            for esc in obs.iter() {
                esc.notify(notification, self)?;
            }
        };
        Ok(())
    }
}

pub trait Notifier {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error>;
}

#[derive(PartialEq)]
pub enum Notification {
    KeyEventAdded(SignedEventMessage),
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

impl From<&Notification> for JustNotification {
    fn from(notification: &Notification) -> Self {
        match notification {
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
