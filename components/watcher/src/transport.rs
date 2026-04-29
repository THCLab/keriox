use std::sync::OnceLock;
use std::time::{Duration, Instant};

use keri_core::oobi::{LocationScheme, Scheme};
use teliox::query::SignedTelQuery;
use tracing::{debug, instrument};

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

/// Process-wide HTTP client for the watcher's TEL transport. See
/// `keri_core::transport::default` for the rationale and the
/// `KERIOX_DISABLE_HTTP_POOL` A/B-toggle env var.
fn shared_http_client() -> reqwest::Client {
    fn build() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .tcp_keepalive(Duration::from_secs(60))
            .build()
            .expect("Failed to build HTTP client")
    }
    if std::env::var_os("KERIOX_DISABLE_HTTP_POOL").is_some() {
        return build();
    }
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(build).clone()
}

pub struct HttpTelTransport;

#[async_trait::async_trait]
impl WatcherTelTransport for HttpTelTransport {
    #[instrument(skip_all, fields(host = location.url.host_str().unwrap_or("?")))]
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, TransportError> {
        let url = match location.scheme {
            Scheme::Http | Scheme::Https => location.url.join("query/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(qry.to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;

        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|_| TransportError::InvalidResponse)?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = status.as_u16(),
            body_bytes = body.len(),
            url = %url,
            "watcher tel send_query completed"
        );
        Ok(body)
    }
}
