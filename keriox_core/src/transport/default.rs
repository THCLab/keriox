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
/// Format a reqwest error with its `source()` chain in one string.
/// `reqwest::Error::to_string()` only shows the top-level message
/// (e.g. "error sending request for url (...)") and discards the
/// actual cause — TLS handshake failure, connection reset, decode
/// failure, etc. — leaving operators no way to tell categories of
/// network failure apart. Used in the `.map_err(...)` of every
/// `.send()` / `.text()` / `.bytes()` call below.
fn fmt_reqwest_error(e: &reqwest::Error) -> String {
    let mut out = format!("{e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(inner) = src {
        out.push_str(" -> ");
        out.push_str(&format!("{inner}"));
        src = inner.source();
    }
    out
}

fn shared_http_client() -> reqwest::Client {
    fn build() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(32)
            .tcp_keepalive(Duration::from_secs(60))
            .user_agent(super::client_version::CLIENT_AGENT)
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

/// The url of a location. A nullified location has none: its endpoint has
/// withdrawn it.
fn base_url<E>(loc: &LocationScheme) -> Result<&url::Url, TransportError<E>> {
    loc.url.as_ref().ok_or_else(|| {
        TransportError::NetworkError(format!(
            "the {:?} location of {} is nullified",
            loc.scheme, loc.eid
        ))
    })
}

/// The url of `path` at a location. Only http(s) locations are reachable
/// by this transport; others, such as the tcp locations KERIpy witnesses
/// advertise, are reported rather than attempted.
fn endpoint<E>(loc: &LocationScheme, path: &str) -> Result<url::Url, TransportError<E>> {
    match loc.scheme {
        Scheme::Http | Scheme::Https => (),
        Scheme::Tcp => return Err(TransportError::UnsupportedScheme(loc.scheme.clone())),
    }
    let base = base_url(loc)?;
    base.join(path).map_err(|e| {
        TransportError::InvalidLocation(format!("{path} at {base} of {}: {e}", loc.eid))
    })
}

#[async_trait::async_trait]
impl<E> Transport<E> for DefaultTransport<E>
where
    E: for<'a> Deserialize<'a> + Send + Sync + std::error::Error + 'static,
{
    #[instrument(skip_all, fields(scheme = ?loc.scheme, host = loc.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<(), TransportError<E>> {
        let path = match &msg {
            Message::Notice(_) => "process",
            Message::Op(op) => match op {
                #[cfg(feature = "query")]
                Op::Query(_) => panic!("can't send query in send_message"),
                #[cfg(feature = "query")]
                Op::Reply(_) => "register",
                // Witnesses and watchers keep no forwards: the application
                // delivers them.
                #[cfg(feature = "mailbox")]
                Op::Exchange(_) => {
                    return Err(TransportError::UnknownError(
                        "forwards are delivered by the application, not posted to a witness or watcher"
                            .into(),
                    ))
                }
            },
        };
        let url = endpoint(&loc, path)?;
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(msg.to_cesr().unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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
    #[instrument(skip_all, fields(host = loc.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQueryMessage,
    ) -> Result<PossibleResponse, TransportError<E>> {
        use crate::actor::possible_response::{parse_response, ResponseError};

        let url = endpoint(&loc, "query")?;

        let op: Message = qry.into();
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(op.to_cesr().unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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

    #[instrument(skip_all, fields(eid = %loc.eid, host = loc.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError<E>> {
        // {url}/oobi/{eid}
        let url = endpoint(&loc, &format!("oobi/{}", loc.eid))?;
        let started = Instant::now();
        let resp = shared_http_client()
            .get(url.clone())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
        let status = resp.status();
        if status.is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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

    #[instrument(skip_all, fields(cid = %cid, eid = %eid, role = ?role, host = loc.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<u8>, TransportError<E>> {
        // {url}/oobi/{cid}/{role}/{eid}
        let role = role.as_str();
        let url = endpoint(&loc, &format!("oobi/{cid}/{role}/{eid}"))?;
        let started = Instant::now();
        let resp = shared_http_client()
            .get(url.clone())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
        let status = resp.status();
        if status.is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;

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
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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

    #[instrument(skip_all, fields(host = loc.url.as_ref().and_then(|url| url.host_str()).unwrap_or("?")))]
    async fn resolve_oobi(&self, loc: LocationScheme, oobi: Oobi) -> Result<(), TransportError<E>> {
        let started = Instant::now();
        let resp = shared_http_client()
            .post(endpoint(&loc, "resolve")?)
            .body(serde_json::to_string(&oobi).unwrap())
            .send()
            .await
            .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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
                .map_err(|e| TransportError::NetworkError(fmt_reqwest_error(&e)))?;
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

#[cfg(all(test, feature = "query"))]
mod test {
    use super::{DefaultTransport, Transport, TransportError};
    use crate::{
        actor::error::ActorError,
        event_message::signed_event_message::{Message, Op},
        oobi::{LocationScheme, Scheme},
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        query::{
            query_event::SignedQueryMessage,
            query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery},
        },
        signer::Signer,
    };

    // Locations come from other parties' signed /loc/scheme replies, so a
    // transport has to cope with any scheme and url they choose to sign.

    fn location(scheme: Scheme, url: &str) -> LocationScheme {
        LocationScheme {
            eid: IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key())),
            scheme,
            url: Some(url::Url::parse(url).unwrap()),
        }
    }

    fn query() -> SignedQueryMessage {
        let signer = Signer::new();
        let asker = BasicPrefix::Ed25519NT(signer.public_key());
        let qry = QueryEvent::new_query(
            QueryRoute::Ksn {
                args: LogsQueryArgs {
                    i: IdentifierPrefix::Basic(asker.clone()),
                    s: None,
                    src: None,
                    limit: None,
                },
                reply_route: String::new(),
            },
            &IdentifierPrefix::Basic(asker.clone()),
            crate::event_message::keri_version::KeriVersion::V1_0,
            crate::actor::prelude::SerializationFormats::JSON,
            crate::actor::prelude::HashFunctionCode::Blake3_256,
        );
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(qry.encode().unwrap()).unwrap());
        SignedQueryMessage::KelQuery(SignedKelQuery::new_nontrans(qry, asker, sig))
    }

    fn reply() -> Message {
        let signer = Signer::new();
        let eid = BasicPrefix::Ed25519NT(signer.public_key());
        let rpy = crate::actor::event_generator::generate_end_role(
            &IdentifierPrefix::Basic(eid.clone()),
            &IdentifierPrefix::Basic(eid.clone()),
            crate::oobi::Role::Witness,
            true,
            crate::event_message::keri_version::KeriVersion::V1_0,
        );
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(rpy.encode().unwrap()).unwrap());
        Message::Op(Op::Reply(
            crate::query::reply_event::SignedReply::new_nontrans(rpy, eid, sig),
        ))
    }

    #[async_std::test]
    async fn sending_a_message_to_a_tcp_location_is_unsupported() {
        let transport = DefaultTransport::<ActorError>::new();

        let result = transport
            .send_message(location(Scheme::Tcp, "tcp://127.0.0.1:5632/"), reply())
            .await;

        assert!(
            matches!(result, Err(TransportError::UnsupportedScheme(Scheme::Tcp))),
            "expected UnsupportedScheme, got {result:?}"
        );
    }

    #[async_std::test]
    async fn sending_a_query_to_a_tcp_location_is_unsupported() {
        let transport = DefaultTransport::<ActorError>::new();

        let result = transport
            .send_query(location(Scheme::Tcp, "tcp://127.0.0.1:5632/"), query())
            .await;

        assert!(
            matches!(result, Err(TransportError::UnsupportedScheme(Scheme::Tcp))),
            "expected UnsupportedScheme, got {result:?}"
        );
    }

    #[async_std::test]
    async fn a_location_url_that_takes_no_path_is_invalid() {
        let transport = DefaultTransport::<ActorError>::new();
        let unusable = || location(Scheme::Http, "data:text/plain,witness");

        let message = transport.send_message(unusable(), reply()).await;
        let query = transport.send_query(unusable(), query()).await;
        let loc_scheme = transport.request_loc_scheme(unusable()).await;

        assert!(
            matches!(message, Err(TransportError::InvalidLocation(_))),
            "message: expected InvalidLocation, got {message:?}"
        );
        assert!(
            matches!(query, Err(TransportError::InvalidLocation(_))),
            "query: expected InvalidLocation, got {query:?}"
        );
        assert!(
            matches!(loc_scheme, Err(TransportError::InvalidLocation(_))),
            "loc scheme: expected InvalidLocation, got {loc_scheme:?}"
        );
    }
}
