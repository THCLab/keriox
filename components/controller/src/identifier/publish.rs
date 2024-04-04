use std::{collections::HashMap, sync::{Arc, Mutex}};

use keri_core::{mailbox::MailboxResponse, prefix::IdentifierPrefix};

use crate::{error::ControllerError, mailbox_updating::MailboxReminder};

use super::Identifier;

pub(crate) struct QueryCache {
	last_asked_index: Arc<Mutex<HashMap<IdentifierPrefix, MailboxReminder>>>,
    last_asked_groups_index: Arc<Mutex<HashMap<IdentifierPrefix, MailboxReminder>>>,
}

impl QueryCache {
	pub(crate) fn new() -> Self {
		Self {
			last_asked_index: Arc::new(Mutex::new(HashMap::new())),
			last_asked_groups_index: Arc::new(Mutex::new(HashMap::new())),
		}
	}

	pub fn last_asked_index(&self, id: &IdentifierPrefix) -> Result<MailboxReminder, ControllerError> {
        Ok(self
            .last_asked_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn last_asked_group_index(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<MailboxReminder, ControllerError> {
        Ok(self
            .last_asked_groups_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?
            .get(id)
            .cloned()
            .unwrap_or_default())
    }

    pub fn update_last_asked_index(
        &self,
        id: IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let mut indexes = self
            .last_asked_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?;
        let reminder = indexes.entry(id).or_default();
        reminder.delegate += res.delegate.len();
        reminder.multisig += res.multisig.len();
        reminder.receipt += res.receipt.len();
        Ok(())
    }

    pub fn update_last_asked_group_index(
        &self,
        id: IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<(), ControllerError> {
        let mut indexes = self
            .last_asked_groups_index
            .lock()
            .map_err(|_| ControllerError::OtherError("Can't lock mutex".to_string()))?;
        let reminder = indexes.entry(id).or_default();
        reminder.delegate += res.delegate.len();
        reminder.multisig += res.multisig.len();
        reminder.receipt += res.receipt.len();
        Ok(())
    }

	
}

impl Identifier {
	pub async fn notify_witnesses(&mut self) -> Result<usize, ControllerError> {
        let mut n = 0;
        while let Some(ev) = self.to_notify.pop() {
            // Elect the leader
            // Leader is identifier with minimal index among all participants who
            // sign event. He will send message to witness.
            let id_idx = self.get_index(&ev.event_message.data).unwrap_or_default();
            let min_sig_idx =
                ev.signatures
                    .iter()
                    .map(|at| at.index.current())
                    .min()
                    .expect("event should have at least one signature") as usize;
            if min_sig_idx == id_idx {
                let witnesses = self.known_events.find_witnesses_at_event(&ev.event_message)?;
                self.communication.publish(&witnesses, &ev).await?;
                n += 1;
            }
        }
        Ok(n)
    }


}