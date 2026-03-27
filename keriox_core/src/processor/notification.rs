use std::{
    collections::HashMap,
    sync::{Arc, OnceLock, RwLock},
};

#[cfg(feature = "query")]
use crate::query::reply_event::SignedReply;

use crate::{
    error::Error,
    event_message::signed_event_message::{
        SignedEventMessage, SignedNontransferableReceipt, SignedTransferableReceipt,
    },
};

/// Internal dispatch strategy — the swappable part.
/// Implement this trait to change how notifications are delivered
/// (e.g. in-process HashMap, SQS queue, etc.).
pub trait NotificationDispatch: Send + Sync {
    fn dispatch(&self, notification: &Notification) -> Result<(), Error>;
    fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: Vec<JustNotification>,
    ) -> Result<(), Error>;
}

/// In-process dispatch: preserves the original HashMap-based behavior.
/// Uses `RwLock` for interior mutability so `register_observer` takes `&self`.
struct InProcessDispatch {
    observers: RwLock<HashMap<JustNotification, Vec<Arc<dyn Notifier + Send + Sync>>>>,
    /// Back-reference to the owning `NotificationBus` so we can pass it
    /// to `Notifier::notify()` callbacks.
    bus: OnceLock<NotificationBus>,
}

impl InProcessDispatch {
    fn new() -> Self {
        Self {
            observers: RwLock::new(HashMap::new()),
            bus: OnceLock::new(),
        }
    }
}

impl NotificationDispatch for InProcessDispatch {
    fn dispatch(&self, notification: &Notification) -> Result<(), Error> {
        let observers = self
            .observers
            .read()
            .map_err(|_| Error::RwLockingError)?;
        let bus = self.bus.get().ok_or_else(|| {
            Error::SemanticError("InProcessDispatch: bus back-reference not set".into())
        })?;
        if let Some(obs) = observers.get(&notification.into()) {
            for esc in obs.iter() {
                esc.notify(notification, bus)?;
            }
        }
        Ok(())
    }

    fn register_observer(
        &self,
        observer: Arc<dyn Notifier + Send + Sync>,
        notifications: Vec<JustNotification>,
    ) -> Result<(), Error> {
        let mut observers = self
            .observers
            .write()
            .map_err(|_| Error::RwLockingError)?;
        for notification in notifications {
            observers
                .entry(notification)
                .or_default()
                .push(observer.clone());
        }
        Ok(())
    }
}

/// Clone-able notification bus that delegates to an internal dispatch strategy.
#[derive(Clone)]
pub struct NotificationBus {
    inner: Arc<dyn NotificationDispatch>,
}

impl NotificationBus {
    /// Create a new bus with the default in-process dispatch.
    pub fn new() -> Self {
        let dispatch = Arc::new(InProcessDispatch::new());
        let bus = Self {
            inner: dispatch.clone(),
        };
        // Set the back-reference so InProcessDispatch can pass &NotificationBus
        // to Notifier::notify() callbacks.
        let _ = dispatch.bus.set(bus.clone());
        bus
    }

    /// Create a bus backed by a custom dispatch implementation.
    pub fn from_dispatch(dispatch: Arc<dyn NotificationDispatch>) -> Self {
        Self { inner: dispatch }
    }

    pub fn register_observer(
        &self,
        escrow: Arc<dyn Notifier + Send + Sync>,
        notification: Vec<JustNotification>,
    ) {
        // register_observer on InProcessDispatch should not fail in practice,
        // but if it does we silently ignore to preserve the existing API signature.
        let _ = self.inner.register_observer(escrow, notification);
    }

    pub fn notify(&self, notification: &Notification) -> Result<(), Error> {
        self.inner.dispatch(notification)
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
