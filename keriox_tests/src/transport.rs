use std::{collections::HashMap, sync::Arc};

use futures::lock::Mutex;
use keri_controller::{
    communication::{IdentifierTelTransport, SendingError},
    LocationScheme,
};
use keri_core::transport::TransportError;
use teliox::{event::verifiable_event::VerifiableEvent, query::SignedTelQuery};
use watcher::{transport::WatcherTelTransport, Watcher};
use witness::Witness;

pub enum TelTestActor {
    Witness(Arc<Witness>),
    Watcher(Arc<Watcher>),
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
            TelTestActor::Watcher(wat) => wat
                .parse_and_process_tel_queries(&input_stream)
                .await
                .unwrap()
                .into_iter()
                .map(|msg| msg.to_string())
                .collect::<Vec<_>>()
                .join(""),
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
                .map_err(|_err| TransportError::NetworkError("Wrong payload".to_string()))?,
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
impl IdentifierTelTransport for TelTestTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        loc: LocationScheme,
    ) -> Result<String, SendingError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError("Wrong address".to_string()).into()),
        };
        let actors = self.actors.lock().await;
        let actor = actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError(
                "Address not found".to_string(),
            ))?;
        let resp = actor.send_query(qry, loc).await?;

        Ok(resp)
    }
    async fn send_tel_event(
        &self,
        qry: VerifiableEvent,
        loc: LocationScheme,
    ) -> Result<(), SendingError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError("Wrong address".to_string()).into()),
        };

        let actors = self.actors.lock().await;
        actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError(
                "Address not found".to_string(),
            ))?
            .send_tel_event(qry, loc)
            .await?;
        Ok(())
    }
}

#[async_trait::async_trait]
impl WatcherTelTransport for TelTestTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, watcher::transport::TransportError> {
        IdentifierTelTransport::send_query(self, qry, location)
            .await
            .map_err(|_e| watcher::transport::TransportError::NetworkError)
    }
}
