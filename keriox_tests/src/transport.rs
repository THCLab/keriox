use std::{collections::HashMap, sync::Arc};

use async_std::sync::Mutex;
use keri_controller::LocationScheme;
use teliox::{
    event::verifiable_event::VerifiableEvent,
    query::SignedTelQuery,
    transport::{GeneralTelTransport, TransportError},
};
use watcher::Watcher;
use witness::Witness;

pub enum TelTestActor {
    Witness(Arc<Witness>),
    Watcher(Watcher),
}

impl TelTestActor {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        _loc: LocationScheme,
    ) -> Result<String, TransportError> {
        let input_stream = qry.to_cesr().unwrap();
        let response = match self {
            TelTestActor::Witness(wit) => wit
                .parse_and_process_tel_queries(&input_stream)
                .unwrap()
                .into_iter()
                .map(|msg| msg.to_string())
                .collect::<Vec<_>>()
                .join(""),
            TelTestActor::Watcher(_wat) => todo!(),
        };
        Ok(response)
    }
    async fn send_tel_event(
        &self,
        event: VerifiableEvent,
        _location: LocationScheme,
    ) -> Result<(), TransportError> {
        let input_stream = event.serialize().unwrap();
        match self {
            TelTestActor::Witness(wit) => wit
                .parse_and_process_tel_events(&input_stream)
                .map_err(|_err| TransportError::NetworkError)?,
            TelTestActor::Watcher(_wat) => todo!(),
        };
        Ok(())
    }
}

pub type TestActorMap = HashMap<(url::Host, u16), TelTestActor>;

/// Used in tests to connect directly to actors without going through the network.
pub struct TelTestTransport {
    actors: Arc<Mutex<TestActorMap>>,
}

impl TelTestTransport {
    pub fn new() -> Self {
        Self {
            actors: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn insert(&self, location: (url::Host, u16), actor: TelTestActor) {
        let mut actors = self.actors.lock().await;
        actors.insert(location, actor);
    }
}

impl Clone for TelTestTransport {
    fn clone(&self) -> Self {
        Self {
            actors: Arc::clone(&self.actors),
        }
    }
}

#[async_trait::async_trait]
impl GeneralTelTransport for TelTestTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        loc: LocationScheme,
    ) -> Result<String, TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };
        let actors = self.actors.lock().await; //.map_err(|_e| TransportError::InvalidResponse)?;
        let actor = actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?;
        let resp = actor
            .send_query(qry, loc)
            .await
            .map_err(|_err| TransportError::InvalidResponse)?;

        Ok(resp)
    }
    async fn send_tel_event(
        &self,
        qry: VerifiableEvent,
        loc: LocationScheme,
    ) -> Result<(), TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        let actors = self.actors.lock().await;
        actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .send_tel_event(qry, loc)
            .await
            .map_err(|_err| TransportError::InvalidResponse)?;

        Ok(())
    }
}
