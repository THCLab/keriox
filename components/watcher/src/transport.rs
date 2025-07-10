use keri_core::oobi::{LocationScheme, Scheme};
use teliox::query::SignedTelQuery;

#[async_trait::async_trait]
pub trait WatcherTelTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, TransportError>;
}

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum TransportError {
    #[error("network error")]
    NetworkError,
    #[error("invalid response")]
    InvalidResponse,
}

pub struct HttpTelTransport;

#[async_trait::async_trait]
impl WatcherTelTransport for HttpTelTransport {
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
}
