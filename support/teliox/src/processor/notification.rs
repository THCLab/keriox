use std::{collections::HashMap, sync::Arc};

use crate::{
    error::Error,
    event::{verifiable_event::VerifiableEvent, Event},
};

pub struct TelNotificationBus {
    observers: HashMap<TelNotificationKind, Vec<Arc<dyn TelNotifier + Send + Sync>>>,
}

impl TelNotificationBus {
    pub fn new() -> Self {
        Self {
            observers: HashMap::new(),
        }
    }
    pub fn register_observer(
        &mut self,
        escrow: Arc<dyn TelNotifier + Send + Sync>,
        notification: Vec<TelNotificationKind>,
    ) {
        notification.into_iter().for_each(|notification| {
            self.observers
                .entry(notification)
                .or_insert_with(Vec::new)
                .push(escrow.clone());
        });
    }

    pub fn notify(&self, notification: &TelNotification) -> Result<(), Error> {
        println!("\nTel notification: {:?}", notification);
        if let Some(obs) = self.observers.get(&notification.into()) {
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
    TelEventAdded(Event),
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
