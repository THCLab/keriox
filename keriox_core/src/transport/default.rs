use std::sync::OnceLock;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tracing::{debug, instrument, trace, warn};

use super::{Transport, TransportError};
#[cfg(feature = "query")]
use crate::actor::possible_response::PossibleResponse;
use crate::{
    actor::parse_op_stream,
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Oobi, Role, Scheme},
    prefix::IdentifierPrefix,
    query::query_event::SignedQueryMessage,
};

/// Process-wide HTTP client with a connection pool, keep-alive, and sane
/// timeouts. Building a fresh `reqwest::Client` per request forces a TCP+TLS
/// handshake every time, which was a major contributor to multi-second OOBI
/// resolution latency. The same `Client` instance reuses connections across
/// every transport call in the process.
///
/// Setting `KERIOX_DISABLE_HTTP_POOL=1` falls back to a fresh `reqwest::Client`
/// per call (pre-optimization behavior). Intended only for A/B perf testing
/// — flip at startup, no recompile needed. `reqwest::Client` is Arc-backed
/// internally, so cloning the cached instance is cheap.
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

/// Default behavior for communication with other actors.
/// Serializes a keri message, does a net request, and deserializes the response.
pub struct DefaultTransport<E> {
    _phantom: std::marker::PhantomData<E>,
}

impl<E> DefaultTransport<E> {
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<E> Default for DefaultTransport<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl<E> Transport<E> for DefaultTransport<E>
where
    E: for<'a> Deserialize<'a> + Send + Sync + std::error::Error + 'static,
{
    #[instrument(skip_all, fields(scheme = ?loc.scheme, host = loc.url.host_str().unwrap_or("?")))]
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<(), TransportError<E>> {
        let url = match loc.scheme {
            Scheme::Http | Scheme::Https => match &msg {
                Message::Notice(_) => loc.url.join("process").unwrap(),
                Message::Op(op) => match op {
                    #[cfg(feature = "query")]
                    Op::Query(_) => panic!("can't send query in send_message"),
                    #[cfg(feature = "query")]
                    Op::Reply(_) => loc.url.join("register").unwrap(),
                    #[cfg(feature = "mailbox")]
                    Op::Exchange(_) => loc.url.join("forward").unwrap(),
                },
            },
            Scheme::Tcp => todo!(),
        };
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(msg.to_cesr().unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = resp.status().as_u16(),
            url = %url,
            "send_message completed"
        );
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;
            if body.is_empty() {
                return Err(TransportError::NetworkError(format!(
                    "Remote returned {} with empty body",
                    status
                )));
            }
            let err =
                serde_json::from_str(&body).map_err(|_e| TransportError::UnknownError(body))?;
            return Err(TransportError::RemoteError(err));
        }
        Ok(())
    }

    #[cfg(feature = "query")]
    #[instrument(skip_all, fields(host = loc.url.host_str().unwrap_or("?")))]
    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQueryMessage,
    ) -> Result<PossibleResponse, TransportError<E>> {
        use crate::actor::possible_response::{parse_response, ResponseError};

        let url = match loc.scheme {
            Scheme::Http | Scheme::Https => loc.url.join("query").unwrap(),
            Scheme::Tcp => todo!(),
        };

        let op: Message = qry.into();
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(op.to_cesr().unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = status.as_u16(),
            body_bytes = body.len(),
            url = %url,
            "send_query completed"
        );
        if status.is_success() {
            match parse_response(&body) {
                Ok(resp) => Ok(resp),
                Err(ResponseError::EmptyResponse) => Err(TransportError::EmptyResponse),
                Err(ResponseError::Unparsable(e)) => Err(TransportError::InvalidResponse(e)),
            }
        } else {
            if body.is_empty() {
                return Err(TransportError::NetworkError(format!(
                    "Remote returned {} with empty body",
                    status
                )));
            }
            let err =
                serde_json::from_str(&body).map_err(|_| TransportError::UnknownError(body))?;
            Err(TransportError::RemoteError(err))
        }
    }

    #[instrument(skip_all, fields(eid = %loc.eid, host = loc.url.host_str().unwrap_or("?")))]
    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError<E>> {
        // {url}/oobi/{eid}
        let url = loc
            .url
            .join("oobi/")
            .unwrap()
            .join(&loc.eid.to_string())
            .unwrap();
        let started = Instant::now();
        let resp = shared_http_client()
            .get(url.clone())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;
            trace!(
                bytes = body.len(),
                preview = %String::from_utf8_lossy(&body[..body.len().min(300)]),
                "loc_scheme response body"
            );
            let ops = parse_op_stream(&body).map_err(|e| {
                warn!(error = ?e, "parse_op_stream failed for loc_scheme response");
                e
            })?;
            debug!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                status = status.as_u16(),
                ops = ops.len(),
                url = %url,
                "request_loc_scheme completed"
            );
            Ok(ops)
        } else {
            let body = resp
                .text()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;
            debug!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                status = status.as_u16(),
                url = %url,
                "request_loc_scheme failed"
            );
            if body.is_empty() {
                return Err(TransportError::NetworkError(format!(
                    "Remote returned {} with empty body",
                    status
                )));
            }
            let err =
                serde_json::from_str(&body).map_err(|_e| TransportError::UnknownError(body))?;
            Err(TransportError::RemoteError(err))
        }
    }

    #[instrument(skip_all, fields(cid = %cid, eid = %eid, role = ?role, host = loc.url.host_str().unwrap_or("?")))]
    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<u8>, TransportError<E>> {
        // {url}/oobi/{cid}/{role}/{eid}
        let url = loc
            .url
            .join("oobi/")
            .unwrap()
            .join(&format!("{}/", &cid.to_string()))
            .unwrap()
            .join(match role {
                Role::Witness => "witness/",
                Role::Watcher => "watcher/",
                Role::Controller => "controller/",
                Role::Messagebox => "messagebox/",
            })
            .unwrap()
            .join(&eid.to_string())
            .unwrap();
        let started = Instant::now();
        let resp = shared_http_client()
            .get(url.clone())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;

            debug!(
                elapsed_ms = started.elapsed().as_millis() as u64,
                status = status.as_u16(),
                bytes = body.len(),
                url = %url,
                "request_end_role completed"
            );
            Ok(body.to_vec())
        } else {
            let body = resp
                .text()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;
            if body.is_empty() {
                return Err(TransportError::NetworkError(format!(
                    "Remote returned {} with empty body",
                    status
                )));
            }
            let err =
                serde_json::from_str(&body).map_err(|_e| TransportError::UnknownError(body))?;
            Err(TransportError::RemoteError(err))
        }
    }

    #[instrument(skip_all, fields(host = loc.url.host_str().unwrap_or("?")))]
    async fn resolve_oobi(&self, loc: LocationScheme, oobi: Oobi) -> Result<(), TransportError<E>> {
        let started = Instant::now();
        let resp = shared_http_client()
            .post(format!("{}resolve", loc.url))
            .body(serde_json::to_string(&oobi).unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(e.to_string()))?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = resp.status().as_u16(),
            "resolve_oobi completed"
        );

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp
                .text()
                .await
                .map_err(|e| TransportError::NetworkError(e.to_string()))?;
            if body.is_empty() {
                return Err(TransportError::NetworkError(format!(
                    "Remote returned {} with empty body",
                    status
                )));
            }
            let err =
                serde_json::from_str(&body).map_err(|_| TransportError::UnknownError(body))?;
            return Err(TransportError::RemoteError(err));
        }
        Ok(())
    }
}
