use keri::{
    actor::{parse_event_stream, parse_op_stream},
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role, Scheme},
    prefix::IdentifierPrefix,
};

use super::{Transport, TransportError};

/// Default behavior for communication with other actors.
/// Serializes a keri message, does a net request, and deserializes the response.
pub struct DefaultTransport;

#[async_trait::async_trait]
impl Transport for DefaultTransport {
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<Vec<Message>, TransportError> {
        let url = match loc.scheme {
            Scheme::Http => match &msg {
                Message::Notice(_) => {
                    // {url}/process
                    loc.url.join("process").unwrap()
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        // {url}/query
                        loc.url.join("query").unwrap()
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
        let body = msg.to_cesr().unwrap();
        let client = reqwest::Client::new();
        let resp = client
            .post(url)
            .body(body)
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?
            .bytes()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        let msgs = parse_event_stream(&resp).map_err(|_| TransportError::InvalidResponse)?;
        Ok(msgs)
    }

    async fn request_loc_scheme(&self, loc: LocationScheme) -> Result<Vec<Op>, TransportError> {
        // {url}/oobi/{eid}
        let url = loc
            .url
            .join("oobi/")
            .unwrap()
            .join(&loc.eid.to_string())
            .unwrap();
        let resp = reqwest::get(url)
            .await
            .map_err(|_| TransportError::NetworkError)?
            .bytes()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        let ops = parse_op_stream(&resp).map_err(|_| TransportError::InvalidResponse)?;
        Ok(ops)
    }

    async fn request_end_role(
        &self,
        loc: LocationScheme,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<Op>, TransportError> {
        // {url}/oobi/{cid}/{role}/{eid}
        let url = loc
            .url
            .join("oobi/")
            .unwrap()
            .join(&cid.to_string())
            .unwrap()
            .join(match role {
                Role::Witness => "witness",
                Role::Watcher => "watcher",
                Role::Controller => "controller",
            })
            .unwrap()
            .join(&eid.to_string())
            .unwrap();
        let resp = reqwest::get(url)
            .await
            .map_err(|_| TransportError::NetworkError)?
            .bytes()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        let ops = parse_op_stream(&resp).map_err(|_| TransportError::InvalidResponse)?;
        Ok(ops)
    }
}
