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
    #[error("{0:?} locations are not supported")]
    UnsupportedScheme(Scheme),
    #[error("invalid location: {0}")]
    InvalidLocation(String),
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
            .user_agent(keri_core::transport::client_version::CLIENT_AGENT)
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
    #[instrument(skip_all, fields(host = location.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, TransportError> {
        let url = match location.scheme {
            // a nullified location has no url to reach
            Scheme::Http | Scheme::Https => location
                .url
                .as_ref()
                .ok_or(TransportError::NetworkError)?
                .join("query/tel")
                .map_err(|e| TransportError::InvalidLocation(e.to_string()))?,
            Scheme::Tcp => return Err(TransportError::UnsupportedScheme(Scheme::Tcp)),
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

#[cfg(test)]
mod test {
    use keri_core::{
        actor::prelude::{HashFunctionCode, SerializationFormats},
        event_message::{keri_version::KeriVersion, msg::KeriEvent, timestamped::Timestamped},
        oobi::{LocationScheme, Scheme},
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        signer::Signer,
    };
    use teliox::query::{SignedTelQuery, TelQueryArgs, TelQueryRoute};

    use super::{HttpTelTransport, TransportError, WatcherTelTransport};

    fn witness_at(scheme: Scheme, url: &str) -> LocationScheme {
        LocationScheme {
            eid: IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key())),
            scheme,
            url: Some(url::Url::parse(url).unwrap()),
        }
    }

    fn tel_query() -> SignedTelQuery {
        let signer = Signer::new();
        let qry = KeriEvent::new(
            KeriVersion::V1_0,
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            Timestamped::new(TelQueryRoute::Tels {
                reply_route: "".into(),
                args: TelQueryArgs { i: None, ri: None },
            }),
        );
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
        SignedTelQuery::new_nontrans(qry, BasicPrefix::Ed25519NT(signer.public_key()), sig)
    }

    #[tokio::test]
    async fn a_tel_query_to_a_tcp_location_is_unsupported() {
        let result = HttpTelTransport
            .send_query(
                tel_query(),
                witness_at(Scheme::Tcp, "tcp://127.0.0.1:5632/"),
            )
            .await;

        assert!(
            matches!(result, Err(TransportError::UnsupportedScheme(Scheme::Tcp))),
            "expected UnsupportedScheme, got {result:?}"
        );
    }

    #[tokio::test]
    async fn a_tel_query_to_a_url_that_takes_no_path_is_invalid() {
        let result = HttpTelTransport
            .send_query(
                tel_query(),
                witness_at(Scheme::Http, "data:text/plain,witness"),
            )
            .await;

        assert!(
            matches!(result, Err(TransportError::InvalidLocation(_))),
            "expected InvalidLocation, got {result:?}"
        );
    }
}
