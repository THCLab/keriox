use futures::future::join_all;
use keri_core::database::{EscrowCreator, EventDatabase};
use keri_core::oobi_manager::storage::OobiStorageBackend;
use teliox::database::TelEventDatabase;

use crate::identifier::Identifier;

use super::MechanicsError;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub async fn notify_witnesses(&mut self) -> Result<usize, MechanicsError> {
        let mut n = 0;
        let to_notify = self.to_notify.iter().filter_map(|ev| {
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
                // For events whose effect on witness config has already been
                // applied to local state (e.g. a freshly finalized rotation),
                // `find_witnesses_at_event` returns DuplicateError when it
                // re-applies the event. Treat that as "use the current
                // witness config" — the state already reflects the event.
                let witnesses = match self
                    .known_events
                    .find_witnesses_at_event(&ev.event_message)
                {
                    Ok(ws) => ws,
                    Err(_) => self
                        .known_events
                        .storage
                        .get_state(&ev.event_message.data.get_prefix())
                        .map(|st| st.witness_config.witnesses)
                        .unwrap_or_default(),
                };
                n += 1;
                Some(self.communication.publish(witnesses, &ev))
            } else {
                None
            }
        });
        join_all(to_notify).await;
        self.to_notify.clear();

        Ok(n)
    }
}
