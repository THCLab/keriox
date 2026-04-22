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
                let witnesses = self
                    .known_events
                    .find_witnesses_at_event(&ev.event_message)
                    .expect("Can't find witnesses");
                n += 1;
                Some(self.communication.publish(witnesses, &ev))
            } else {
                None
            }
        });

        let results = join_all(to_notify).await;
        for res in results {
            res?;
        }
        self.to_notify.clear();

        Ok(n)
    }
}
