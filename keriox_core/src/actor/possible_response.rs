use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    error::Error,
    event_message::{cesr_adapter::ParseError, signed_event_message::Notice},
};
use crate::{event_message::signed_event_message::Op, query::reply_event::SignedReply};

#[cfg(feature = "mailbox")]
use crate::mailbox::MailboxResponse;

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
    #[cfg(feature = "mailbox")]
    Mbx(MailboxResponse),
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
            #[cfg(feature = "mailbox")]
            PossibleResponse::Mbx(mbx) => {
                let receipts_stream = mbx
                    .receipt
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::NontransferableRct(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                let multisig_stream = mbx
                    .multisig
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::Event(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                let delegate_stream = mbx
                    .delegate
                    .clone()
                    .into_iter()
                    .map(|rct| Message::Notice(Notice::Event(rct)).to_cesr())
                    .collect::<Result<Vec<Vec<u8>>, Error>>()?
                    .concat();
                #[derive(Serialize)]
                struct GroupedResponse {
                    receipt: String,
                    multisig: String,
                    delegate: String,
                }
                serde_json::to_vec(&GroupedResponse {
                    receipt: String::from_utf8(receipts_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                    multisig: String::from_utf8(multisig_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                    delegate: String::from_utf8(delegate_stream)
                        .map_err(|e| Error::SerializationError(e.to_string()))?,
                })
                .map_err(|e| Error::SerializationError(e.to_string()))?
            }
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

    #[cfg(feature = "mailbox")]
    match parse_mailbox_response(response) {
        Ok(res) => return Ok(res),
        Err(_) => {}
    };

    Ok(match parse_reply_stream(response.as_bytes()) {
        Ok(a) if a.is_empty() => return Err(ResponseError::EmptyResponse),
        Ok(rep) => PossibleResponse::Ksn(rep[0].clone()),
        Err(_e) => {
            let events = parse_event_stream(response.as_bytes())?;
            PossibleResponse::Kel(events)
        }
    })
}

#[cfg(feature = "mailbox")]
pub fn parse_mailbox_response(response: &str) -> Result<PossibleResponse, ParseError> {
    use crate::actor::parse_event_stream;

    #[derive(Deserialize, Debug)]
    struct GroupedResponse {
        receipt: String,
        multisig: String,
        delegate: String,
    }
    let res: GroupedResponse =
        serde_json::from_str(&response).map_err(|e| ParseError::DeserializeError(e.to_string()))?;
    let receipts = parse_event_stream(res.receipt.as_bytes())?
        .into_iter()
        .map(|rct| {
            if let Message::Notice(Notice::NontransferableRct(rct)) = rct {
                rct
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    let multisig = parse_event_stream(res.multisig.as_bytes())?
        .into_iter()
        .map(|msg| {
            if let Message::Notice(Notice::Event(event)) = msg {
                event
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    let delegate = parse_event_stream(res.delegate.as_bytes())?
        .into_iter()
        .map(|msg| {
            if let Message::Notice(Notice::Event(event)) = msg {
                event
            } else {
                unreachable!()
            }
        })
        .collect::<Vec<_>>();
    Ok(PossibleResponse::Mbx(MailboxResponse {
        receipt: receipts,
        multisig: multisig,
        delegate,
    }))
}
