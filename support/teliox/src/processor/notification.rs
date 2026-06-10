use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Weak},
};

use crate::{error::Error, event::verifiable_event::VerifiableEvent};
#[derive(Clone)]
pub struct TelNotificationBus {
    observers: Arc<RwLock<HashMap<TelNotificationKind, Vec<Arc<dyn TelNotifier + Send + Sync>>>>>,
}

impl TelNotificationBus {
    pub fn new() -> Self {
        Self {
            observers: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    pub fn register_observer(
        &self,
        escrow: Arc<dyn TelNotifier + Send + Sync>,
        notifications: Vec<TelNotificationKind>,
    ) -> Result<(), Error> {
        for notification in notifications {
            self.observers
                .write()
                .map_err(|_e| Error::RwLockingError)?
                .entry(notification)
                .or_insert_with(Vec::new)
                .push(escrow.clone());
        }
        Ok(())
    }

    pub fn notify(&self, notification: &TelNotification) -> Result<(), Error> {
        if let Some(obs) = self
            .observers
            .read()
            .map_err(|_e| Error::RwLockingError)?
            .get(&notification.into())
        {
            for esc in obs.iter() {
                esc.notify(notification, self)?;
            }
        };
        Ok(())
    }
}

impl TelNotificationBus {
    /// A non-owning handle to this bus.
    ///
    /// Observers registered on the bus are owned by it (`Arc`), so an
    /// observer that also needs to publish back to its own bus must hold a
    /// weak handle — holding the bus directly creates a reference cycle that
    /// keeps the bus, every observer, and everything they reference
    /// (including database handles) alive forever.
    pub fn downgrade(&self) -> WeakTelNotificationBus {
        WeakTelNotificationBus {
            observers: Arc::downgrade(&self.observers),
        }
    }
}

/// Non-owning [`TelNotificationBus`] handle for observers that publish back
/// to the bus they are registered on. See [`TelNotificationBus::downgrade`].
#[derive(Clone)]
pub struct WeakTelNotificationBus {
    observers:
        Weak<RwLock<HashMap<TelNotificationKind, Vec<Arc<dyn TelNotifier + Send + Sync>>>>>,
}

impl WeakTelNotificationBus {
    /// The owning bus, if it is still alive.
    pub fn upgrade(&self) -> Option<TelNotificationBus> {
        self.observers
            .upgrade()
            .map(|observers| TelNotificationBus { observers })
    }

    /// Notify through the bus if it is still alive; a dropped bus has no
    /// listeners left, so the notification is skipped.
    pub fn notify(&self, notification: &TelNotification) -> Result<(), Error> {
        match self.upgrade() {
            Some(bus) => bus.notify(notification),
            None => Ok(()),
        }
    }
}

impl Default for TelNotificationBus {
    fn default() -> Self {
        Self::new()
    }
}

pub trait TelNotifier {
    fn notify(&self, notification: &TelNotification, bus: &TelNotificationBus)
        -> Result<(), Error>;
}

#[derive(PartialEq, Debug, Clone)]
pub enum TelNotification {
    MissingRegistry(VerifiableEvent),
    MissingIssuer(VerifiableEvent),
    OutOfOrder(VerifiableEvent),
    TelEventAdded(VerifiableEvent),
}

#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub enum TelNotificationKind {
    MissingRegistry,
    MissingIssuer,
    OutOfOrder,
    TelEventAdded,
}

impl From<&TelNotification> for TelNotificationKind {
    fn from(notification: &TelNotification) -> Self {
        match notification {
            TelNotification::MissingRegistry(_) => Self::MissingRegistry,
            TelNotification::MissingIssuer(_) => Self::MissingIssuer,
            TelNotification::OutOfOrder(_) => Self::OutOfOrder,
            TelNotification::TelEventAdded(_) => Self::TelEventAdded,
        }
    }
}
