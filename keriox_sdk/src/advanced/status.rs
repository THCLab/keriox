//! Public identifier state served by witnesses and watchers.
//!
//! Witnesses and watchers that advertise the `abandonment` feature on
//! `GET /info` answer `GET /identifiers/{aid}/state` without any querier
//! identity. The answer is a hint, not proof: it tells an operator, or a
//! client with no identity of its own, what that server has seen. Anything
//! that must rely on it verifies the key event log itself, through an
//! authenticated watcher query and [`Identifier::find_state`].
//!
//! [`Identifier::find_state`]: crate::advanced::Identifier::find_state

use keri_controller::IdentifierPrefix;
use keri_core::event_message::keri_version::KeriVersion;
pub use keri_core::state::{Abandonment, IdentifierStatus};
use url::Url;

use crate::advanced::error::{Error, Result};

/// Feature name a witness or watcher lists on `GET /info` when it refuses
/// events after an abandonment and serves `GET /identifiers/{aid}/state`.
pub const ABANDONMENT_FEATURE: &str = "abandonment";

/// Feature name a witness or watcher lists on `GET /info` when it reads
/// KERI 2.0 messages.
pub const KERI2_FEATURE: &str = "keri2";

/// A GET request naming this keriox release, as every keriox client does.
async fn get(url: Url) -> reqwest::Result<reqwest::Response> {
    reqwest::Client::builder()
        .user_agent(keri_core::transport::client_version::CLIENT_AGENT)
        .build()?
        .get(url)
        .send()
        .await
}

/// What `base` (a witness or watcher URL) reports about `id`; `None` when it
/// has never seen the identifier.
///
/// # Errors
/// - [`Error::Other`] if the server cannot be reached, answers with an
///   error, or does not serve the endpoint.
pub async fn fetch_identifier_status(
    base: &Url,
    id: &IdentifierPrefix,
) -> Result<Option<IdentifierStatus>> {
    let url = base
        .join(&format!("identifiers/{id}/state"))
        .map_err(|e| Error::Other(format!("invalid server URL {base}: {e}")))?;
    let response = get(url.clone())
        .await
        .map_err(|e| Error::Other(format!("cannot reach {url}: {e}")))?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let response = response
        .error_for_status()
        .map_err(|e| Error::Other(format!("{url}: {e}")))?;
    response
        .json()
        .await
        .map(Some)
        .map_err(|e| Error::Other(format!("unexpected answer from {url}: {e}")))
}

/// Whether `base` (a witness or watcher URL) enforces abandonment: it lists
/// [`ABANDONMENT_FEATURE`] on `GET /info`. A server that does not would
/// still receipt or serve events that follow an abandonment, so check every
/// witness and watcher before abandoning an identifier.
///
/// # Errors
/// - [`Error::Other`] if the server cannot be reached or answers with an
///   error.
pub async fn supports_abandonment(base: &Url) -> Result<bool> {
    supports_feature(base, ABANDONMENT_FEATURE).await
}

/// Whether `base` (a witness or watcher URL) reads KERI 2.0 messages: it
/// lists [`KERI2_FEATURE`] on `GET /info`. Write KERI 2.0 only once every
/// witness and watcher an identifier uses does.
///
/// # Errors
/// - [`Error::Other`] if the server cannot be reached or answers with an
///   error.
pub async fn supports_keri2(base: &Url) -> Result<bool> {
    supports_feature(base, KERI2_FEATURE).await
}

/// The KERI version `base` (a witness or watcher URL) writes its own
/// messages in, from `keri_version` on `GET /info`. A server that does not
/// report one predates the switch and writes KERI 1.0.
///
/// # Errors
/// - [`Error::Other`] if the server cannot be reached or answers with an
///   error.
pub async fn server_keri_version(base: &Url) -> Result<KeriVersion> {
    Ok(info(base).await?.keri_version)
}

/// The KERI version to write to `servers`: 2.0 once every one of them writes
/// 2.0, which operators switch only when every reader on the network reads
/// it. A server that writes 1.0, or cannot be reached, keeps it at 1.0, and
/// so does an empty list.
pub async fn agreed_keri_version(servers: &[Url]) -> KeriVersion {
    if servers.is_empty() {
        return KeriVersion::V1;
    }
    for server in servers {
        if !matches!(server_keri_version(server).await, Ok(KeriVersion::V2)) {
            return KeriVersion::V1;
        }
    }
    KeriVersion::V2
}

/// Whether `base` lists `feature` on `GET /info`.
async fn supports_feature(base: &Url, feature: &str) -> Result<bool> {
    Ok(info(base).await?.features.iter().any(|f| f == feature))
}

/// What `base` reports on `GET /info`.
struct Info {
    features: Vec<String>,
    keri_version: KeriVersion,
}

async fn info(base: &Url) -> Result<Info> {
    #[derive(serde::Deserialize)]
    struct Answer {
        #[serde(default)]
        features: Vec<String>,
        #[serde(default)]
        keri_version: KeriVersion,
    }

    let url = base
        .join("info")
        .map_err(|e| Error::Other(format!("invalid server URL {base}: {e}")))?;
    let answer: Answer = get(url.clone())
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|e| Error::Other(format!("cannot reach {url}: {e}")))?
        .json()
        .await
        .map_err(|e| Error::Other(format!("unexpected answer from {url}: {e}")))?;
    Ok(Info {
        features: answer.features,
        keri_version: answer.keri_version,
    })
}
