use keri::{
    actor::{
        parse_op_stream,
        simple_controller::{parse_response, PossibleResponse}, parse_event_stream,
    },
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role, Scheme},
    prefix::IdentifierPrefix,
    query::query_event::SignedQuery,
};
use serde::Deserialize;

use super::{Transport, TransportError};

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
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<(), TransportError<E>> {
        let url = match loc.scheme {
            Scheme::Http => match &msg {
                Message::Notice(_) => {
                    // {url}/process
                    loc.url.join("process").unwrap()
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        panic!("can't send query in send_message");
                    }
                    Op::Reply(_) => {
                        // {url}/register
                        loc.url.join("register").unwrap()
                    }
                    Op::Exchange(_) => {
                        // {url}/forward
                        loc.url.join("forward").unwrap()
                    }
                },
            },
            Scheme::Tcp => todo!(),
        };
        let resp = reqwest::Client::new()
            .post(url)
            .body(msg.to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if !resp.status().is_success() {
            let body = resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            let err = serde_json::from_str(&body).map_err(|_| TransportError::NetworkError)?;
            return Err(TransportError::RemoteError(err));
        }
        Ok(())
    }

    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQuery,
    ) -> Result<PossibleResponse, TransportError<E>> {
        let url = match loc.scheme {
            Scheme::Http => {
                // {url}/query
                loc.url.join("query").unwrap()
            }
            Scheme::Tcp => todo!(),
        };
        let resp = reqwest::Client::new()
            .post(url)
            .body(Message::Op(Op::Query(qry)).to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if status.is_success() {
            let resp = parse_response(&body).map_err(|_| TransportError::InvalidResponse)?;
            Ok(resp)
        } else {
            let err = serde_json::from_str(&body).map_err(|_| TransportError::InvalidResponse)?;
            Err(TransportError::RemoteError(err))
        }
    }

    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError<E>> {
        // {url}/oobi/{eid}
        let url = loc
            .url
            .join("oobi/")
            .unwrap()
            .join(&loc.eid.to_string())
            .unwrap();
        let resp = reqwest::get(url)
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if resp.status().is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            let ops = parse_op_stream(&body).map_err(|_| TransportError::InvalidResponse)?;
            Ok(ops)
        } else {
            let body = resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            let err = serde_json::from_str(&body).map_err(|_| TransportError::InvalidResponse)?;
            Err(TransportError::RemoteError(err))
        }
    }

    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Message>, TransportError<E>> {
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
            })
            .unwrap()
            .join(&eid.to_string())
            .unwrap();
        let resp = reqwest::get(url)
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if resp.status().is_success() {
            let body = resp
                .bytes()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            let ops = parse_event_stream(&body).map_err(|_| TransportError::InvalidResponse)?;
            Ok(ops)
        } else {
            let body = resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            let err = serde_json::from_str(&body).map_err(|_| TransportError::InvalidResponse)?;
            Err(TransportError::RemoteError(err))
        }
    }
}
