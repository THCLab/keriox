use keri::{
    actor::{
        parse_op_stream,
        simple_controller::{parse_response, PossibleResponse},
    },
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Role, Scheme},
    prefix::IdentifierPrefix,
    query::query_event::SignedQuery,
};

use super::{Transport, TransportError};

/// Default behavior for communication with other actors.
/// Serializes a keri message, does a net request, and deserializes the response.
pub struct DefaultTransport;

#[async_trait::async_trait]
impl Transport for DefaultTransport {
    async fn send_message(&self, loc: LocationScheme, msg: Message) -> Result<(), TransportError> {
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
        reqwest::Client::new()
            .post(url)
            .body(msg.to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        Ok(())
    }

    async fn send_query(
        &self,
        loc: LocationScheme,
        qry: SignedQuery,
    ) -> Result<PossibleResponse, TransportError> {
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
            .map_err(|_| TransportError::NetworkError)?
            .text()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        let resp = parse_response(&resp).map_err(|_| TransportError::InvalidResponse)?;
        Ok(resp)
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

    // async fn resolve_loc_scheme(&self, loc: LocationScheme) -> Result<(), TransportError> {
    //     // {url}/resolve
    //     let url = loc.url.join("resolve").unwrap();
    //     let body = todo!("loc_scheme to bytes");
    //     reqwest::Client::new()
    //         .post(url)
    //         .body(body)
    //         .send()
    //         .await
    //         .map_err(|_| TransportError::NetworkError)?;
    //     Ok(())
    // }
}
