use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
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
