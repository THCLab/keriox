use std::{collections::HashMap, sync::Arc};

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;

use crate::{
    error::Error,
    event_message::signed_event_message::{
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
};

pub struct NotificationBus {
    observers: HashMap<JustNotification, Vec<Arc<dyn Notifier + Send + Sync>>>,
}

impl NotificationBus {
    pub fn new() -> Self {
        Self {
            observers: HashMap::new(),
        }
    }
    pub fn register_observer(
        &mut self,
        escrow: Arc<dyn Notifier + Send + Sync>,
        notification: Vec<JustNotification>,
    ) {
        notification.into_iter().for_each(|notification| {
            self.observers
                .entry(notification)
                .or_default()
                .push(escrow.clone());
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

impl Default for NotificationBus {
    fn default() -> Self {
        Self::new()
    }
}

pub trait Notifier {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error>;
}

#[derive(PartialEq, Debug, Clone)]
pub enum Notification {
    KeyEventAdded(SignedEventMessage),
    OutOfOrder(SignedEventMessage),
    PartiallySigned(SignedEventMessage),
    PartiallyWitnessed(SignedEventMessage),
    ReceiptAccepted,
    ReceiptEscrowed,
    ReceiptOutOfOrder(SignedNontransferableReceipt),
    TransReceiptOutOfOrder(SignedTransferableReceipt),
    DupliciousEvent(SignedEventMessage),
    MissingDelegatingEvent(SignedEventMessage),
    #[cfg(feature = "query")]
    KsnOutOfOrder(SignedReply),
}

#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub enum JustNotification {
    KeyEventAdded,
    OutOfOrder,
    PartiallySigned,
    PartiallyWitnessed,
    ReceiptAccepted,
    ReceiptEscrowed,
    ReceiptOutOfOrder,
    TransReceiptOutOfOrder,
    DuplicitousEvent,
    MissingDelegatingEvent,
    #[cfg(feature = "query")]
    KsnOutOfOrder,
    #[cfg(feature = "query")]
    KsnUpdated,
    #[cfg(feature = "oobi")]
    GotOobi,
    #[cfg(feature = "query")]
    ReplayLog,
    #[cfg(feature = "query")]
    ReplyKsn,
    #[cfg(feature = "query")]
    GetMailbox,
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
            Notification::DupliciousEvent(_) => JustNotification::DuplicitousEvent,
            #[cfg(feature = "query")]
            Notification::KsnOutOfOrder(_) => JustNotification::KsnOutOfOrder,
            Notification::MissingDelegatingEvent(_) => JustNotification::MissingDelegatingEvent,
        }
    }
}
