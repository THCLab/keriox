use std::{collections::HashMap, sync::{Arc}};

use async_std::sync::Mutex;
use controller::LocationScheme;
use teliox::{transport::{GeneralTelTransport, TransportError}, query::SignedTelQuery, event::verifiable_event::VerifiableEvent};
use watcher::Watcher;
use witness::{Witness};

pub enum TelTestActor {
	Witness(Arc<Witness>),
	Watcher(Watcher),
}

#[async_trait::async_trait]
impl GeneralTelTransport for TelTestActor {
     async fn send_query(&self, qry: SignedTelQuery, loc: LocationScheme) -> Result<String, TransportError> {
        let input_stream = qry.to_cesr().unwrap();
        let response = match self {
            TelTestActor::Witness(wit) => wit.parse_and_process_tel_queries(&input_stream).unwrap().into_iter().map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join(""),
            TelTestActor::Watcher(wat) => todo!(),
        };
        Ok(response)
    }
    async fn send_tel_event(&self, event: VerifiableEvent, location: LocationScheme) -> Result<String, TransportError> {
        let input_stream = event.serialize().unwrap();
        let response = match self {
            TelTestActor::Witness(wit) => wit.parse_and_process_tel_events(&input_stream).unwrap().into_iter().map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join(""),
            TelTestActor::Watcher(wat) => todo!(),
        };
        Ok(response)
    }

}

pub type TestActorMap =
    HashMap<(url::Host, u16), Arc<TelTestActor>>;

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

    pub async fn insert(&self, location: (url::Host, u16), actor: Arc<TelTestActor>) {
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
impl GeneralTelTransport for TelTestTransport
{

    async fn send_query(&self, qry: SignedTelQuery, loc: LocationScheme) -> Result<String, TransportError> {
        // todo!()
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };
        let actors = self.actors.lock().await;//.map_err(|_e| TransportError::InvalidResponse)?;
        let actor = actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?;
        let resp = actor.send_query(qry, loc)
            .await
            .map_err(|_err| TransportError::InvalidResponse)?;

        Ok(resp)
    }
    async fn send_tel_event(&self, qry: VerifiableEvent, loc: LocationScheme) -> Result<String, TransportError> {
        let (host, port) = match loc.url.origin() {
            url::Origin::Tuple(_scheme, host, port) => (host, port),
            _ => return Err(TransportError::NetworkError),
        };

        let actors = self.actors.lock().await;
        let resp = actors
            .get(&(host, port))
            .ok_or(TransportError::NetworkError)?
            .send_tel_event(qry, loc)
            .await
            .map_err(|_err| TransportError::InvalidResponse)?;

        Ok(resp)
    }
}