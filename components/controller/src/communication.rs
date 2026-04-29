use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use futures::future::join_all;
use tracing::{debug, instrument};
use keri_core::{
    actor::{error::ActorError, parse_event_stream, possible_response::PossibleResponse},
    database::{EscrowCreator, EventDatabase},
    event_message::signed_event_message::{Message, Notice, Op, SignedEventMessage},
    oobi::{EndRole, LocationScheme, Oobi, Scheme},
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix},
    query::{
        mailbox::SignedMailboxQuery,
        query_event::{SignedKelQuery, SignedQueryMessage},
    },
    transport::{Transport, TransportError},
};
use teliox::{
    database::TelEventDatabase, event::verifiable_event::VerifiableEvent, query::SignedTelQuery,
};

use crate::{
    error::ControllerError,
    identifier::mechanics::MechanicsError,
    known_events::{KnownEvents, OobiRetrieveError},
};

#[derive(Debug, thiserror::Error)]
pub enum SendingError {
    #[error("Actor doesn't have identifier {missing} oobi")]
    WatcherDosntHaveOobi { missing: IdentifierPrefix },

    #[error("Actor internal error: {0}")]
    ActorInternalError(#[from] ActorError),

    #[error("Transport error: {0}")]
    TransportError(keri_core::transport::TransportError),

    #[error("Http request error: {0}")]
    HTTPError(#[from] reqwest::Error),

    #[error(transparent)]
    OobiError(#[from] OobiRetrieveError),

    #[error("Invalid url: {0}")]
    InvalidUrl(#[from] url::ParseError),
}

impl From<TransportError> for SendingError {
    fn from(value: TransportError) -> Self {
        match value {
            TransportError::RemoteError(ActorError::NoIdentState { prefix }) => {
                Self::WatcherDosntHaveOobi { missing: prefix }
            }
            TransportError::RemoteError(internal_error) => Self::ActorInternalError(internal_error),
            e => Self::TransportError(e),
        }
    }
}

pub struct Communication<D, T, S>
where
    D: EventDatabase + EscrowCreator + 'static,
    T: TelEventDatabase + 'static,
    S: OobiStorageBackend,
{
    pub events: Arc<KnownEvents<D, T, S>>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn IdentifierTelTransport + Send + Sync>,
}

impl<D, T, S> Communication<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    pub fn new(
        known_events: Arc<KnownEvents<D, T, S>>,
        transport: Box<dyn Transport<ActorError> + Send + Sync>,
        tel_transport: Box<dyn IdentifierTelTransport + Send + Sync>,
    ) -> Self {
        Communication {
            events: known_events,
            transport,
            tel_transport,
        }
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), MechanicsError> {
        let oobis = self.transport.request_loc_scheme(lc.clone()).await?;
        for oobi in oobis {
            self.events.save(&Message::Op(oobi))?;
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_end_role(&self, er: &EndRole) -> Result<(), MechanicsError> {
        let EndRole { cid, role, eid } = er.clone();
        // TODO what if more than one
        let loc = self
            .events
            .get_loc_schemas(&eid)
            .map_err(SendingError::OobiError)?
            .first()
            .ok_or(SendingError::OobiError(OobiRetrieveError::MissingOobi(
                cid.clone(),
                None,
            )))?
            .clone();
        let response = self.transport.request_end_role(loc, cid, role, eid).await?;

        let msgs = parse_event_stream(response.as_ref()).map_err(|e| {
            MechanicsError::OtherError(format!(
                "Can't parse response while oobi resolving: {}",
                e.to_string()
            ))
        })?;
        for msg in msgs {
            // TODO This ignore signatures. Add verification.
            if let Message::Op(Op::Reply(signed_oobi)) = msg {
                self.events.save_oobi(&signed_oobi)?;
            } else {
                self.events.save(&msg)?;
            }
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_oobi(&self, oobi: &Oobi) -> Result<(), MechanicsError> {
        match oobi {
            Oobi::Location(loc) => self.resolve_loc_schema(loc).await,
            Oobi::EndRole(er) => self.resolve_end_role(er).await,
        }
    }

    pub async fn send_message_to(
        &self,
        id: IdentifierPrefix,
        scheme: Scheme,
        msg: Message,
    ) -> Result<(), SendingError> {
        let loc = self.events.find_location(&id, scheme)?;
        self.transport.send_message(loc, msg).await?;
        Ok(())
    }

    pub async fn send_query_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        query: SignedKelQuery,
    ) -> Result<PossibleResponse, SendingError> {
        let loc = self.events.find_location(id, scheme)?;
        Ok(self
            .transport
            .send_query(loc, SignedQueryMessage::KelQuery(query))
            .await?)
    }

    pub async fn send_management_query_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        query: SignedMailboxQuery,
    ) -> Result<PossibleResponse, SendingError> {
        let loc = self.events.find_location(id, scheme)?;
        Ok(self
            .transport
            .send_query(loc, SignedQueryMessage::MailboxQuery(query))
            .await?)
    }

    async fn send_oobi_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        oobi: Oobi,
    ) -> Result<(), SendingError> {
        let loc = self.events.find_location(id, scheme)?;
        self.transport.resolve_oobi(loc, oobi).await?;
        Ok(())
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    pub async fn publish(
        &self,
        witness_prefixes: Vec<BasicPrefix>,
        message: &SignedEventMessage,
    ) -> Result<(), MechanicsError> {
        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let (prefix, sn, digest) = (
            message.event_message.data.get_prefix(),
            message.event_message.data.get_sn(),
            message.event_message.digest(),
        );
        let rcts_from_db = self
            .events
            .find_receipt(&prefix, sn, &digest?)?
            .map(|rct| Message::Notice(Notice::NontransferableRct(rct)));

        let messages_to_send = if let Some(receipt) = rcts_from_db {
            vec![Message::Notice(Notice::Event(message.clone())), receipt]
        } else {
            vec![Message::Notice(Notice::Event(message.clone()))]
        };

        join_all(
            itertools::iproduct!(messages_to_send, witness_prefixes).map(
                |(message, witness_id)| {
                    self.send_message_to(
                        IdentifierPrefix::Basic(witness_id.clone()),
                        Scheme::Http,
                        message.clone(),
                    )
                },
            ),
        )
        .await;

        Ok(())
    }

    /// Sends identifier's endpoint information to identifiers's watchers.
    // TODO use stream instead of json
    pub async fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        oobi: &Oobi,
    ) -> Result<(), ControllerError> {
        for watcher in self.events.get_watchers(id)?.iter() {
            self.send_oobi_to(watcher, Scheme::Http, oobi.clone())
                .await?;
        }

        Ok(())
    }

    pub async fn send_tel_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, SendingError> {
        self.tel_transport.send_query(qry, location).await
    }

    pub async fn send_tel_event(
        &self,
        event: VerifiableEvent,
        location: LocationScheme,
    ) -> Result<(), SendingError> {
        self.tel_transport.send_tel_event(event, location).await
    }
}

#[async_trait::async_trait]
pub trait IdentifierTelTransport {
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, SendingError>;
    async fn send_tel_event(
        &self,
        qry: VerifiableEvent,
        location: LocationScheme,
    ) -> Result<(), SendingError>;
}

pub struct HTTPTelTransport;

/// Process-wide HTTP client for the controller's TEL transport. See
/// `keri_core::transport::default` for rationale and the
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

#[async_trait::async_trait]
impl IdentifierTelTransport for HTTPTelTransport {
    #[instrument(skip_all, fields(host = location.url.host_str().unwrap_or("?")))]
    async fn send_query(
        &self,
        qry: SignedTelQuery,
        location: LocationScheme,
    ) -> Result<String, SendingError> {
        let url = match location.scheme {
            Scheme::Http | Scheme::Https => location.url.join("query/tel")?,
            Scheme::Tcp => todo!(),
        };
        let started = Instant::now();
        let resp = shared_http_client()
            .post(url.clone())
            .body(qry.to_cesr().unwrap())
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = status.as_u16(),
            body_bytes = body.len(),
            url = %url,
            "controller tel send_query completed"
        );
        Ok(body)
    }

    #[instrument(skip_all, fields(host = location.url.host_str().unwrap_or("?")))]
    async fn send_tel_event(
        &self,
        event: VerifiableEvent,
        location: LocationScheme,
    ) -> Result<(), SendingError> {
        let url = match location.scheme {
            Scheme::Http | Scheme::Https => location.url.join("process/tel")?,
            Scheme::Tcp => todo!(),
        };
        let started = Instant::now();
        let query = event.serialize().unwrap();
        let resp = shared_http_client()
            .post(url.clone())
            .body(query)
            .send()
            .await?;
        let status = resp.status();
        resp.text().await?;
        debug!(
            elapsed_ms = started.elapsed().as_millis() as u64,
            status = status.as_u16(),
            url = %url,
            "controller tel send_tel_event completed"
        );

        Ok(())
    }
}
