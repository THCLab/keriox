use std::{collections::VecDeque, sync::Mutex};

use crate::error::Error;

use super::notification::{Notification, NotificationBus, Notifier};

// Helper struct for appending data that need response.
#[derive(Default)]
pub struct Responder<D> {
    needs_response: Mutex<VecDeque<D>>,
}

impl<D> Responder<D> {
    pub fn new() -> Self {
        Self {
            needs_response: Mutex::new(VecDeque::new()),
        }
    }

    pub fn get_data_to_respond(&self) -> Option<D> {
        self.needs_response.lock().unwrap().pop_front()
    }

    pub fn append(&self, element: D) -> Result<(), Error> {
        self.needs_response.lock().unwrap().push_back(element);
        Ok(())
    }
}

impl Notifier for Responder<Notification> {
    fn notify(&self, notification: &Notification, _bus: &NotificationBus) -> Result<(), Error> {
        self.needs_response
            .lock()
            .unwrap()
            .push_back((*notification).clone());
        Ok(())
    }
}
