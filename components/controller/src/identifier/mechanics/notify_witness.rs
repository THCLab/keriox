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
        // Build the publish set, re-hydrating each event from the DB
        // rather than sending the cached copy queued in `to_notify`. A
        // delegated `dip`/`drt` is queued at inception — before the
        // delegator anchors it — so the cached copy has no source-seal
        // couple. The stored event (via `get_event_at_sn`) carries the
        // seal that `finalize_delegation` attached when accepting the
        // event out of escrow; without it a witness cannot validate the
        // delegation, never issues a receipt, and the delegatee's KEL
        // stays unservable to watchers. Non-delegated events are
        // unaffected (their reloaded form is identical).
        let mut jobs = Vec::new();
        for ev in &self.to_notify {
            // Elect the leader: identifier with the minimal index among
            // all participants who sign the event sends it to witnesses.
            let id_idx = self.get_index(&ev.event_message.data).unwrap_or_default();
            let min_sig_idx = ev
                .signatures
                .iter()
                .map(|at| at.index.current())
                .min()
                .expect("event should have at least one signature") as usize;
            if min_sig_idx != id_idx {
                continue;
            }
            // For events whose effect on witness config has already been
            // applied to local state (e.g. a freshly finalized rotation),
            // `find_witnesses_at_event` returns DuplicateError when it
            // re-applies the event. Treat that as "use the current
            // witness config" — the state already reflects the event.
            let witnesses = match self.known_events.find_witnesses_at_event(&ev.event_message) {
                Ok(ws) => ws,
                Err(_) => self
                    .known_events
                    .storage
                    .get_state(&ev.event_message.data.get_prefix())
                    .map(|st| st.witness_config.witnesses)
                    .unwrap_or_default(),
            };
            // Re-hydrate by digest from the event log, not by sn from the
            // finalized KEL: a delegated `dip`/`drt` is published to its
            // witnesses *before* it is accepted (it can only become fully
            // witnessed once they receipt it), so it is not in the
            // finalized KEL yet — but the log already holds it with its
            // source seal. `get_event_at_sn` would miss it and we'd fall
            // back to the cached seal-less copy, so the witness could
            // never validate the delegation and the event would stay
            // escrowed forever.
            let to_send = ev
                .event_message
                .digest()
                .ok()
                .and_then(|digest| self.known_events.storage.get_event_by_digest(&digest))
                .map(|t| t.signed_event_message)
                .unwrap_or_else(|| ev.clone());
            n += 1;
            jobs.push((witnesses, to_send));
        }
        join_all(
            jobs.iter()
                .map(|(witnesses, ev)| self.communication.publish(witnesses.clone(), ev)),
        )
        .await;
        self.to_notify.clear();

        Ok(n)
    }
}
