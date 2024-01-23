use keri_core::oobi::{LocationScheme, Scheme};

use crate::{event::verifiable_event::VerifiableEvent, query::SignedTelQuery};

pub struct TelTransport;

#[async_trait::async_trait]
impl GeneralTelTransport for TelTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, TransportError> {
        let url = match location.scheme {
            Scheme::Http => location.url.join("query/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
        let resp = reqwest::Client::new()
            .post(url)
            .body(qry.to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;

        resp.text()
            .await
            .map_err(|_| TransportError::InvalidResponse)
    }

    async fn send_tel_event(
        &self,
        qry: VerifiableEvent,
        location: LocationScheme,
    ) -> Result<(), TransportError> {
        let url = match location.scheme {
            Scheme::Http => location.url.join("process/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
        let client = reqwest::Client::new();
        let query = qry
            .serialize()
            .map_err(|_e| TransportError::InvalidResponse)?;
        let resp = client
            .post(url)
            .body(query)
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        resp.text()
            .await
            .map_err(|_| TransportError::InvalidResponse)?;

        Ok(())
    }
}

pub enum HttpTransportError {
    NetworkError,
}

#[async_trait::async_trait]
pub trait GeneralTelTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, TransportError>;
    async fn send_tel_event(
        &self,
        qry: VerifiableEvent,
        location: LocationScheme,
    ) -> Result<(), TransportError>;
}

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum TransportError {
    #[error("network error")]
    NetworkError,
    #[error("invalid response")]
    InvalidResponse,
}
