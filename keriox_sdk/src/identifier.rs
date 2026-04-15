use keri_controller::{
    identifier::query::QueryResponse, BasicPrefix, IdentifierPrefix, LocationScheme, Oobi,
    SelfSigningPrefix,
};
use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    event::sections::seal::EventSeal,
    event::KeyEvent,
    event_message::{
        msg::TypedEvent, signature::Signature, signed_event_message::Notice, EventTypeTag,
    },
    query::{mailbox::MailboxQuery, query_event::QueryEvent},
    state::IdentifierState,
};
use teliox::{
    query::TelQueryEvent,
    state::{vc_state::TelState, ManagerTelState},
};

use crate::error::Result;

pub use keri_controller::identifier::query::WatcherResponseError;
pub use keri_controller::mailbox_updating::ActionRequired;

use keri_core::prefix::IndexedSignature;

/// Concrete identifier wrapping `keri_controller::controller::RedbIdentifier`.
pub struct Identifier {
    pub(crate) inner: keri_controller::RedbIdentifier,
}

impl Identifier {
    // ── Identity ────────────────────────────────────────────────────────────

    pub fn id(&self) -> &IdentifierPrefix {
        self.inner.id()
    }

    pub fn registry_id(&self) -> Option<&IdentifierPrefix> {
        self.inner.registry_id()
    }

    // ── State / KEL accessors ────────────────────────────────────────────────

    /// Returns accepted `IdentifierState` for any known identifier.
    pub fn find_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState> {
        Ok(self.inner.find_state(id)?)
    }

    pub fn current_public_keys(&self) -> Result<Vec<BasicPrefix>> {
        Ok(self.inner.current_public_keys()?)
    }

    pub fn witnesses(&self) -> impl Iterator<Item = BasicPrefix> + '_ {
        self.inner.witnesses()
    }

    pub fn watchers(&self) -> Result<Vec<IdentifierPrefix>> {
        Ok(self.inner.watchers()?)
    }

    /// Returns own identifier's accepted KEL with receipts.
    pub fn get_own_kel(&self) -> Option<Vec<Notice>> {
        self.inner.get_own_kel()
    }

    /// Returns any identifier's accepted KEL with receipts.
    pub fn get_kel(&self, id: &IdentifierPrefix) -> Option<Vec<Notice>> {
        self.inner.get_kel(id)
    }

    // ── KEL management ──────────────────────────────────────────────────────

    /// Generate an interaction event anchoring the given SAIs.
    pub fn anchor(&self, payload: &[SelfAddressingIdentifier]) -> Result<String> {
        Ok(self.inner.anchor(payload)?)
    }

    /// Generate a rotation event.
    pub async fn rotate(
        &self,
        current_keys: Vec<BasicPrefix>,
        new_next_keys: Vec<BasicPrefix>,
        new_next_threshold: u64,
        witness_to_add: Vec<LocationScheme>,
        witness_to_remove: Vec<BasicPrefix>,
        witness_threshold: u64,
    ) -> Result<String> {
        Ok(self
            .inner
            .rotate(
                current_keys,
                new_next_keys,
                new_next_threshold,
                witness_to_add,
                witness_to_remove,
                witness_threshold,
            )
            .await?)
    }

    /// Finalise a rotation event (sign + save + queue for witness notification).
    pub async fn finalize_rotate(&mut self, event: &[u8], sig: SelfSigningPrefix) -> Result<()> {
        Ok(self.inner.finalize_rotate(event, sig).await?)
    }

    /// Finalise an interaction event (sign + save + queue for witness notification).
    pub async fn finalize_anchor(&mut self, event: &[u8], sig: SelfSigningPrefix) -> Result<()> {
        Ok(self.inner.finalize_anchor(event, sig).await?)
    }

    /// Send pending events to witnesses, returns the number of events sent.
    pub async fn notify_witnesses(&mut self) -> Result<usize> {
        Ok(self.inner.notify_witnesses().await?)
    }

    // ── OOBI / watcher ──────────────────────────────────────────────────────

    pub async fn resolve_oobi(&self, oobi: &Oobi) -> Result<()> {
        Ok(self.inner.resolve_oobi(oobi).await?)
    }

    pub async fn send_oobi_to_watcher(&self, id: &IdentifierPrefix, oobi: &Oobi) -> Result<()> {
        Ok(self.inner.send_oobi_to_watcher(id, oobi).await?)
    }

    /// Generate an `end_role_add` reply event for the given watcher.
    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String> {
        Ok(self.inner.add_watcher(watcher_id)?)
    }

    /// Generate an `end_role_cut` reply event for the given watcher.
    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String> {
        Ok(self.inner.remove_watcher(watcher_id)?)
    }

    /// Sign and send the `end_role_add` reply to the watcher.
    pub async fn finalize_add_watcher(&self, event: &[u8], sig: SelfSigningPrefix) -> Result<()> {
        Ok(self.inner.finalize_add_watcher(event, sig).await?)
    }

    // ── Signing / verification ──────────────────────────────────────────────

    /// Return CESR stream containing the payload + transferable signature.
    pub fn sign_to_cesr(&self, data: &str, signatures: &[SelfSigningPrefix]) -> Result<String> {
        Ok(self.inner.sign_to_cesr(data, signatures)?)
    }

    /// Build a `Signature` from raw bytes + `SelfSigningPrefix`es.
    pub fn sign_data(&self, data: &[u8], signatures: &[SelfSigningPrefix]) -> Result<Signature> {
        Ok(self.inner.sign_data(data, signatures)?)
    }

    /// Verify a CESR stream (payload + attached signatures) against known KEL.
    pub fn verify_from_cesr(&self, stream: &[u8]) -> Result<()> {
        Ok(self.inner.verify_from_cesr(stream)?)
    }

    // ── TEL / Credential ────────────────────────────────────────────────────

    /// Generate a `vcp` inception event and anchor `ixn`.
    pub fn incept_registry(
        &mut self,
    ) -> Result<(IdentifierPrefix, TypedEvent<EventTypeTag, KeyEvent>)> {
        Ok(self.inner.incept_registry()?)
    }

    /// Finalise registry inception (sign + save the anchor ixn).
    pub async fn finalize_incept_registry(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<()> {
        Ok(self.inner.finalize_incept_registry(event, sig).await?)
    }

    /// Send TEL events to backers (witnesses).
    pub async fn notify_backers(&self) -> Result<()> {
        Ok(self.inner.notify_backers().await?)
    }

    /// Generate `iss` event + anchor `ixn`. Returns (vc_id, ixn_event).
    pub fn issue(
        &self,
        credential_digest: SelfAddressingIdentifier,
    ) -> Result<(IdentifierPrefix, TypedEvent<EventTypeTag, KeyEvent>)> {
        Ok(self.inner.issue(credential_digest)?)
    }

    /// Generate `rev` event + anchor `ixn` (encoded). Returns encoded ixn bytes.
    pub fn revoke(&self, credential_sai: &SelfAddressingIdentifier) -> Result<Vec<u8>> {
        Ok(self.inner.revoke(credential_sai)?)
    }

    /// Build a TEL query event.
    pub fn query_tel(
        &self,
        registry_id: IdentifierPrefix,
        vc_identifier: IdentifierPrefix,
    ) -> Result<TelQueryEvent> {
        Ok(self.inner.query_tel(registry_id, vc_identifier)?)
    }

    /// Sign + send TEL query, process the response.
    pub async fn finalize_query_tel(
        &self,
        qry: TelQueryEvent,
        sig: SelfSigningPrefix,
    ) -> Result<()> {
        Ok(self.inner.finalize_query_tel(qry, sig).await?)
    }

    /// Look up a VC's current `TelState` in the local TEL.
    pub fn find_vc_state(&self, vc_hash: &SelfAddressingIdentifier) -> Result<Option<TelState>> {
        Ok(self.inner.find_vc_state(vc_hash)?)
    }

    /// Look up a registry's management TEL state.
    pub fn find_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<ManagerTelState>> {
        Ok(self.inner.find_management_tel_state(id)?)
    }

    // ── Mailbox / watcher queries ────────────────────────────────────────────

    /// Generate mailbox query events for each of the given witnesses.
    pub fn query_mailbox(
        &self,
        identifier: &IdentifierPrefix,
        witnesses: &[BasicPrefix],
    ) -> Result<Vec<MailboxQuery>> {
        Ok(self.inner.query_mailbox(identifier, witnesses)?)
    }

    /// Sign + send mailbox queries, process responses. Returns required actions.
    pub async fn finalize_query_mailbox(
        &mut self,
        queries: Vec<(MailboxQuery, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>> {
        Ok(self.inner.finalize_query_mailbox(queries).await?)
    }

    /// Generate watcher query events for an identifier.
    pub fn query_watchers(&self, about_who: &EventSeal) -> Result<Vec<QueryEvent>> {
        Ok(self.inner.query_watchers(about_who)?)
    }

    /// Sign + send watcher queries, process responses.
    pub async fn finalize_query(
        &self,
        queries: Vec<(QueryEvent, SelfSigningPrefix)>,
    ) -> (QueryResponse, Vec<WatcherResponseError>) {
        self.inner.finalize_query(queries).await
    }

    /// Generate a full-log watcher query for an identifier.
    pub fn query_full_log(
        &self,
        id: &IdentifierPrefix,
        watcher: IdentifierPrefix,
    ) -> Result<QueryEvent> {
        Ok(self.inner.query_full_log(id, watcher)?)
    }

    // ── Delegation / group ────────────────────────────────────────────────────

    /// Generate a delegated (or group) inception event and exchange messages.
    ///
    /// If `delegator` is provided, a DIP (delegated inception) is created and
    /// a delegation-request exchange is appended to the returned list.
    /// Returns `(serialized_event, vec_of_serialized_exchanges)`.
    pub fn incept_group(
        &self,
        participants: Vec<IdentifierPrefix>,
        signature_threshold: u64,
        next_keys_threshold: Option<u64>,
        initial_witnesses: Option<Vec<BasicPrefix>>,
        witness_threshold: Option<u64>,
        delegator: Option<IdentifierPrefix>,
    ) -> Result<(String, Vec<String>)> {
        Ok(self.inner.incept_group(
            participants,
            signature_threshold,
            next_keys_threshold,
            initial_witnesses,
            witness_threshold,
            delegator,
        )?)
    }

    /// Finalise a group/delegated inception event. Returns the new prefix.
    pub async fn finalize_group_incept(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, Signature)>,
    ) -> Result<IdentifierPrefix> {
        Ok(self
            .inner
            .finalize_group_incept(group_event, sig, exchanges)
            .await?)
    }

    /// Finalise a group event (e.g. a delegating IXN).
    pub async fn finalize_group_event(
        &mut self,
        group_event: &[u8],
        sig: SelfSigningPrefix,
        exchanges: Vec<(Vec<u8>, Signature)>,
    ) -> Result<()> {
        Ok(self
            .inner
            .finalize_group_event(group_event, sig, exchanges)
            .await?)
    }

    /// Finalise an exchange message (e.g. delegation approval forwarding).
    pub async fn finalize_exchange(
        &self,
        exchange: &[u8],
        exn_signature: Signature,
        data_signature: IndexedSignature,
    ) -> Result<()> {
        Ok(self
            .inner
            .finalize_exchange(exchange, exn_signature, data_signature)
            .await?)
    }

    /// Create a transferable signature at a specific key index.
    pub fn sign_with_index(
        &self,
        signature: SelfSigningPrefix,
        key_index: u16,
    ) -> Result<Signature> {
        Ok(self.inner.sign_with_index(signature, key_index)?)
    }

    /// Save an external notice (e.g. a delegator's KEL event) into the local DB.
    pub fn save_notice(&self, notice: &Notice) -> Result<()> {
        use keri_core::event_message::signed_event_message::Message;
        self.inner
            .known_events
            .save(&Message::Notice(notice.clone()))?;
        Ok(())
    }

    // ── OOBI location helpers ──────────────────────────────────────────────

    /// Get known location schemes for an identifier.
    pub fn get_location(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        self.inner
            .get_location(id)
            .map_err(|e| crate::error::Error::Other(e.to_string()))
    }

    /// Get location schemes for identifiers serving a specific role for `id`.
    pub fn get_role_location(
        &self,
        id: &IdentifierPrefix,
        role: keri_core::oobi::Role,
    ) -> Result<Vec<LocationScheme>> {
        Ok(self.inner.get_role_location(id, role)?)
    }

    /// Get end-role entries for an identifier and role.
    pub fn get_end_role(
        &self,
        id: &IdentifierPrefix,
        role: keri_core::oobi::Role,
    ) -> Result<Vec<keri_controller::EndRole>> {
        Ok(self.inner.get_end_role(id, role)?)
    }

    // ── Low-level seal helpers ───────────────────────────────────────────────

    pub fn get_last_establishment_event_seal(&self) -> Result<EventSeal> {
        Ok(self.inner.get_last_establishment_event_seal()?)
    }

    pub fn get_last_event_seal(&self) -> Result<EventSeal> {
        Ok(self.inner.get_last_event_seal()?)
    }
}
