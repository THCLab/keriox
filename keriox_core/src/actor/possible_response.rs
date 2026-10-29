use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event_message::cesr_adapter::ParseError,
};
use crate::{event_message::signed_event_message::Op, query::reply_event::SignedReply};

use super::prelude::Message;

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum ResponseError {
    #[error("Empty response")]
    EmptyResponse,
    #[error("Can't parse response: {0}")]
    Unparsable(#[from] ParseError),
}

#[derive(PartialEq, Debug, Clone)]
pub enum PossibleResponse {
    Kel(Vec<Message>),
    Ksn(SignedReply),
}

impl PossibleResponse {
    fn display(&self) -> Result<Vec<u8>, Error> {
        Ok(match self {
            PossibleResponse::Kel(kel) => kel
                .iter()
                .map(|message| -> Result<_, Error> { message.to_cesr() })
                .collect::<Result<Vec<Vec<u8>>, Error>>()?
                .concat(),
            PossibleResponse::Ksn(ksn) => Message::Op(Op::Reply(ksn.clone())).to_cesr()?,
        })
    }
}

impl fmt::Display for PossibleResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = self.display().map_err(|_e| fmt::Error)?;
        f.write_str(&String::from_utf8(str).map_err(|_e| fmt::Error)?)?;
        Ok(())
    }
}

#[cfg(feature = "query")]
pub fn parse_response(response: &str) -> Result<PossibleResponse, ResponseError> {
    use crate::actor::parse_event_stream;

    use super::parse_reply_stream;

    Ok(match parse_reply_stream(response.as_bytes()) {
        Ok(a) if a.is_empty() => return Err(ResponseError::EmptyResponse),
        Ok(rep) => PossibleResponse::Ksn(rep[0].clone()),
        Err(_e) => {
            let events = parse_event_stream(response.as_bytes())?;
            PossibleResponse::Kel(events)
        }
    })
}

