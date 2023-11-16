use crate::{
    error::Error,
    query::{SignedTelQuery, TelQueryEvent},
};

use self::{manager_event::ManagerTelEventMessage, vc_event::VCEventMessage};
use cesrox::{group::Group, parse_many};
use keri::{
    event_message::{cesr_adapter::ParseError, signature::get_signatures},
    prefix::IdentifierPrefix,
};
use said::SelfAddressingIdentifier;
use serde::{Deserialize, Serialize};

pub mod manager_event;
pub mod vc_event;
pub mod verifiable_event;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum Event {
    Management(ManagerTelEventMessage),
    Vc(VCEventMessage),
}

impl Event {
    pub fn get_digest(&self) -> Result<SelfAddressingIdentifier, Error> {
        Ok(match self {
            Event::Management(man) => man.digest(),
            Event::Vc(ev) => ev.digest(),
        }?)
    }
    pub fn get_prefix(&self) -> IdentifierPrefix {
        match self {
            Event::Management(man) => man.data.prefix.clone(),
            Event::Vc(ev) => ev.data.data.prefix.clone(),
        }
    }

    pub fn get_sn(&self) -> u64 {
        match self {
            Event::Management(man) => man.data.sn,
            Event::Vc(ev) => ev.data.data.sn,
        }
    }

    pub fn get_registry_id(&self) -> Result<IdentifierPrefix, Error> {
        Ok(match &self {
            Event::Management(ref man) => man.data.prefix.clone(),
            Event::Vc(ref vc) => vc.data.data.registry_id()?,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        match self {
            Event::Management(man) => Ok(man.encode()?),
            Event::Vc(ev) => Ok(ev.encode()?),
        }
    }
}

fn signed_tel_query(
    qry: TelQueryEvent,
    mut attachments: Vec<Group>,
) -> Result<SignedTelQuery, ParseError> {
    let att = attachments
        .pop()
        .ok_or_else(|| ParseError::AttachmentError("Missing attachment".into()))?;
    let sigs = get_signatures(att)?;
    Ok(SignedTelQuery {
        query: qry,
        // TODO what if more than one?
        signature: sigs
            .get(0)
            .ok_or(ParseError::AttachmentError(
                "Missing signatures".to_string(),
            ))?
            .to_owned(),
    })
}

pub fn parse_tel_query_stream(stream: &[u8]) -> Result<Vec<SignedTelQuery>, ParseError> {
    let (_rest, queries) = parse_many(stream).unwrap();
    queries
        .iter()
        .map(|qry| {
            let q: TelQueryEvent = match &qry.payload {
                cesrox::payload::Payload::JSON(json) => serde_json::from_slice(&json).unwrap(),
                cesrox::payload::Payload::CBOR(_) => todo!(),
                cesrox::payload::Payload::MGPK(_) => todo!(),
            };
            signed_tel_query(q, qry.attachments.clone())
        })
        .collect()
}
