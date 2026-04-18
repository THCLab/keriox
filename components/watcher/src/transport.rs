use std::time::Duration;

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

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .build()
        .expect("Failed to build HTTP client")
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
            Scheme::Http | Scheme::Https => location.url.join("query/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
        let resp = http_client()
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
