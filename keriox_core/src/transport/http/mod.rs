use bytes::Bytes;
use serde::Deserialize;

use super::TransportError;
use crate::{
    actor::simple_controller::{parse_response, PossibleResponse},
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Scheme},
    query::query_event::SignedQuery,
};

mod default;

pub enum HttpReq {
    Get { url: url::Url },
    Post { url: url::Url, body: Vec<u8> },
}

pub struct HttpResp {
    code: u16,
    body: Bytes,
}

#[async_trait::async_trait]
pub trait HttpTransport {
    async fn send_http_request(&self, req: HttpReq) -> Result<HttpResp, HttpTransportError>;

    async fn send_message<E>(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<(), TransportError<E>>
    where
        E: for<'de> Deserialize<'de>,
    {
        let url = match loc.scheme {
            Scheme::Http => match &msg {
                Message::Notice(_) => {
                    // {url}/process
                    loc.url.join("process").unwrap()
                }
                Message::Op(op) => match op {
                    #[cfg(feature = "query")]
                    Op::Query(_) => {
                        panic!("can't send query in send_message");
                    }
                    #[cfg(feature = "query")]
                    Op::Reply(_) => {
                        // {url}/register
                        loc.url.join("register").unwrap()
                    }
                    #[cfg(feature = "mailbox")]
                    Op::Exchange(_) => {
                        // {url}/forward
                        loc.url.join("forward").unwrap()
                    }
                },
            },
            Scheme::Tcp => todo!(),
        };
        let resp = self
            .send_http_request(HttpReq::Post {
                url,
                body: msg.to_cesr().unwrap(),
            })
            .await
            .map_err(|_| TransportError::NetworkError)?;
        match resp.code {
            200..=299 => Ok(()),
            _ => {
                let err = serde_json::from_slice(&resp.body)
                    .map_err(|_| TransportError::InvalidResponse)?;
                Err(TransportError::RemoteError(err))
            }
        }
    }

    #[cfg(feature = "query")]
    async fn send_query<E>(
        &self,
        loc: LocationScheme,
        qry: SignedQuery,
    ) -> Result<PossibleResponse, TransportError<E>>
    where
        E: for<'de> Deserialize<'de>,
    {
        let url = match loc.scheme {
            Scheme::Http => {
                // {url}/query
                loc.url.join("query").unwrap()
            }
            Scheme::Tcp => todo!(),
        };
        let resp = self
            .send_http_request(HttpReq::Post {
                url,
                body: Message::Op(Op::Query(qry)).to_cesr().unwrap(),
            })
            .await
            .map_err(|_| TransportError::NetworkError)?;
        match resp.code {
            200..=299 => {
                let resp = parse_response(
                    &String::from_utf8(resp.body.to_vec())
                        .map_err(|_| TransportError::InvalidResponse)?,
                )
                .map_err(|_| TransportError::InvalidResponse)?;
                Ok(resp)
            }
            _ => {
                let err =
                    serde_json::from_slice(&resp.body).map_err(|_| TransportError::NetworkError)?;
                Err(TransportError::RemoteError(err))
            }
        }
    }
}

pub enum HttpTransportError {
    NetworkError,
}
