use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    event::{event_data::EventData, sections::seal::EventSeal},
    event_message::signed_event_message::{Notice, SignedEventMessage},
    oobi::Oobi,
    prefix::{BasicPrefix, IdentifierPrefix},
    state::IdentifierState,
};
use teliox::state::{vc_state::TelState, ManagerTelState};

use crate::{communication::Communication, error::ControllerError, known_events::KnownEvents};

use self::mechanics::{query_mailbox::QueryCache, MechanicsError};

pub mod mechanics;
pub mod query;
pub mod signing;
pub mod tel;

pub struct Identifier {
    id: IdentifierPrefix,
    registry_id: Option<IdentifierPrefix>,
    known_events: Arc<KnownEvents>,
    communication: Arc<Communication>,
    pub to_notify: Vec<SignedEventMessage>,
    query_cache: QueryCache,
    /// Cached identifier state. It saves the state of identifier, event if last
    /// event isn't accepted in the KEL yet (e.g. if there are no witness
    /// receipts yet.)
    cached_state: IdentifierState,
    pub(crate) broadcasted_rcts: HashSet<(SelfAddressingIdentifier, BasicPrefix, IdentifierPrefix)>,
    cached_identifiers: HashMap<IdentifierPrefix, IdentifierState>,
}

impl Identifier {
    pub fn new(
        id: IdentifierPrefix,
        known_events: Arc<KnownEvents>,
        communication: Arc<Communication>,
    ) -> Self {
        // Load events that need to be notified to witnesses
        let events_to_notice: Vec<_> = known_events
            .partially_witnessed_escrow
            .get_partially_witnessed_events()
            .iter()
            .filter(|ev| ev.event_message.data.prefix == id)
            .cloned()
            .collect();
        // Cache state. It can be not fully witnessed.
        let state = if let Ok(state) = known_events.get_state(&id) {
            state
        } else {
            let not_accepted_incept = events_to_notice.iter().find_map(|ev| {
                if let EventData::Icp(_icp) = &ev.event_message.data.event_data {
                    Some(ev.event_message.clone())
                } else {
                    None
                }
            });
            IdentifierState::default()
                .apply(&not_accepted_incept.unwrap())
                .unwrap()
        };
        Self {
            id,
            known_events,
            communication,
            to_notify: events_to_notice,
            query_cache: QueryCache::new(),
            cached_state: state,
            registry_id: None,
            broadcasted_rcts: HashSet::new(),
            cached_identifiers: HashMap::new(),
        }
    }

    pub async fn resolve_oobi(&self, oobi: &Oobi) -> Result<(), MechanicsError> {
        self.communication.resolve_oobi(oobi).await
    }

    pub async fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        oobi: &Oobi,
    ) -> Result<(), ControllerError> {
        self.communication.send_oobi_to_watcher(id, oobi).await
    }

    pub fn id(&self) -> &IdentifierPrefix {
        &self.id
    }

    pub fn registry_id(&self) -> Option<&IdentifierPrefix> {
        self.registry_id.as_ref()
    }

    /// Returns accepted IdentifierState of identifier.
    pub fn find_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState, MechanicsError> {
        self.known_events.get_state(id)
    }

    pub fn find_management_tel_state(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<ManagerTelState>, ControllerError> {
        Ok(self.known_events.tel.get_management_tel_state(id)?)
    }

    pub fn find_vc_state(
        &self,
        vc_hash: &SelfAddressingIdentifier,
    ) -> Result<Option<TelState>, ControllerError> {
        Ok(self.known_events.tel.get_vc_state(vc_hash)?)
    }

    pub fn current_public_keys(&self) -> Result<Vec<BasicPrefix>, ControllerError> {
        Ok(self.known_events.current_public_keys(&self.id).unwrap())
    }

    pub fn witnesses(&self) -> impl Iterator<Item = BasicPrefix> {
        self.cached_state
            .witness_config
            .witnesses
            .clone()
            .into_iter()
    }

    pub fn watchers(&self) -> Result<Vec<IdentifierPrefix>, ControllerError> {
        self.known_events.get_watchers(&self.id)
    }

    /// Returns own identifier accepted Key Event Log
    pub fn get_kel(&self) -> Option<Vec<Notice>> {
        self.known_events.find_kel_with_receipts(&self.id)
    }

    pub fn get_last_establishment_event_seal(&self) -> Result<EventSeal, ControllerError> {
        self.known_events
            .storage
            .get_last_establishment_event_seal(&self.id)
            .ok_or(ControllerError::UnknownIdentifierError)
    }

    pub fn get_last_event_seal(&self) -> Result<EventSeal, MechanicsError> {
        let state = self.known_events.get_state(self.id())?;
        Ok(EventSeal {
            prefix: state.prefix,
            sn: state.sn,
            event_digest: state.last_event_digest,
        })
    }
}
