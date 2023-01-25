use version::Versional;

#[cfg(feature = "mailbox")]
use crate::mailbox::exchange::{Exchange, ExchangeMessage, ForwardTopic, FwdArgs};
#[cfg(feature = "oobi")]
use crate::oobi::{EndRole, Role};
#[cfg(feature = "query")]
use crate::query::reply_event::{ReplyEvent, ReplyRoute};
use crate::{
    error::Error,
    event::{
        sections::{
            seal::{DigestSeal, Seal},
            threshold::{SignatureThreshold, WeightedThreshold},
        },
        KeyEvent,
    },
    event_message::{event_msg_builder::EventMsgBuilder, msg::KeriEvent, EventTypeTag},
    prefix::{BasicPrefix, IdentifierPrefix},
    sai::{derivation::SelfAddressing, SelfAddressingPrefix},
    state::IdentifierState,
};

// todo add setting signing threshold
pub fn incept(
    public_keys: Vec<BasicPrefix>,
    next_pub_keys: Vec<BasicPrefix>,
    witnesses: Vec<BasicPrefix>,
    witness_threshold: u64,
    delegator_id: Option<&IdentifierPrefix>,
) -> Result<String, Error> {
    let event_builder = match delegator_id {
        Some(delegator) => EventMsgBuilder::new(EventTypeTag::Dip).with_delegator(delegator),
        None => EventMsgBuilder::new(EventTypeTag::Icp),
    };
    let serialized_icp = event_builder
        .with_keys(public_keys)
        .with_next_keys(next_pub_keys)
        .with_witness_list(witnesses.as_slice())
        .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
        .build()
        .map_err(|e| Error::EventGenerationError(e.to_string()))?
        .serialize()
        .map_err(|e| Error::EventGenerationError(e.to_string()))?;

    let icp = String::from_utf8(serialized_icp)
        .map_err(|e| Error::EventGenerationError(e.to_string()))?;
    Ok(icp)
}

pub fn incept_with_next_hashes(
    public_keys: Vec<BasicPrefix>,
    signature_threshold: &SignatureThreshold,
    next_pub_keys: Vec<SelfAddressingPrefix>,
    witnesses: Vec<BasicPrefix>,
    witness_threshold: u64,
    delegator_id: Option<&IdentifierPrefix>,
) -> Result<KeriEvent<KeyEvent>, Error> {
    // Check if threshold is possible to achive
    match signature_threshold {
        SignatureThreshold::Simple(t) => {
            if t > &(public_keys.len() as u64) {
                return Err(Error::EventGenerationError(
                    "Improper signature threshold".into(),
                ));
            }
        }
        SignatureThreshold::Weighted(w) => {
            let length = match w {
                WeightedThreshold::Single(s) => s.length(),
                WeightedThreshold::Multi(m) => m.length(),
            };
            if length > public_keys.len() {
                return Err(Error::EventGenerationError(
                    "Improper signature threshold".into(),
                ));
            }
        }
    };

    if witness_threshold > witnesses.len() as u64 {
        return Err(Error::EventGenerationError(
            "Improper witness threshold".into(),
        ));
    };

    let event_builder = match delegator_id {
        Some(delegator) => EventMsgBuilder::new(EventTypeTag::Dip).with_delegator(delegator),
        None => EventMsgBuilder::new(EventTypeTag::Icp),
    };
    event_builder
        .with_keys(public_keys)
        .with_threshold(signature_threshold)
        .with_next_keys_hashes(next_pub_keys)
        .with_witness_list(witnesses.as_slice())
        .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
        .build()
        .map_err(|e| Error::EventGenerationError(e.to_string()))
}

pub fn rotate(
    state: IdentifierState,
    current_keys: Vec<BasicPrefix>,
    new_next_keys: Vec<BasicPrefix>,
    witness_to_add: Vec<BasicPrefix>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
) -> Result<String, Error> {
    let rot = make_rotation(
        state,
        current_keys,
        new_next_keys,
        witness_to_add,
        witness_to_remove,
        witness_threshold,
    )?
    .serialize()
    .map_err(|e| Error::EventGenerationError(e.to_string()))?;
    String::from_utf8(rot).map_err(|e| Error::EventGenerationError(e.to_string()))
}

fn make_rotation(
    state: IdentifierState,
    current_keys: Vec<BasicPrefix>,
    new_next_keys: Vec<BasicPrefix>,
    witness_to_add: Vec<BasicPrefix>,
    witness_to_remove: Vec<BasicPrefix>,
    witness_threshold: u64,
) -> Result<KeriEvent<KeyEvent>, Error> {
    EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&state.last_event_digest)
        .with_keys(current_keys)
        .with_next_keys(new_next_keys)
        .with_witness_to_add(&witness_to_add)
        .with_witness_to_remove(&witness_to_remove)
        .with_witness_threshold(&SignatureThreshold::Simple(witness_threshold))
        .build()
        .map_err(|e| Error::EventGenerationError(e.to_string()))
}

pub fn anchor(state: IdentifierState, payload: &[SelfAddressingPrefix]) -> Result<String, Error> {
    let seal_list = payload
        .iter()
        .map(|seal| {
            Seal::Digest(DigestSeal {
                dig: seal.to_owned(),
            })
        })
        .collect();
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&state.last_event_digest)
        .with_seal(seal_list)
        .build()
        .map_err(|e| Error::EventGenerationError(e.to_string()))?
        .serialize()
        .map_err(|e| Error::EventGenerationError(e.to_string()))?;
    String::from_utf8(ixn).map_err(|e| Error::EventGenerationError(e.to_string()))
}

pub fn anchor_with_seal(
    state: IdentifierState,
    seal_list: &[Seal],
) -> Result<KeriEvent<KeyEvent>, Error> {
    let ev = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&state.prefix)
        .with_sn(state.sn + 1)
        .with_previous_event(&state.last_event_digest)
        .with_seal(seal_list.to_owned())
        .build()
        .map_err(|e| Error::EventGenerationError(e.to_string()))?;
    Ok(ev)
}

#[cfg(feature = "oobi")]
/// Generate reply event used to add role to given identifier.
pub fn generate_end_role(
    controller_id: &IdentifierPrefix,
    watcher_id: &IdentifierPrefix,
    role: Role,
    enabled: bool,
) -> Result<ReplyEvent, Error> {
    use version::serialization_info::SerializationFormats;

    let end_role = EndRole {
        cid: controller_id.clone(),
        role,
        eid: watcher_id.clone(),
    };
    let reply_route = if enabled {
        ReplyRoute::EndRoleAdd(end_role)
    } else {
        ReplyRoute::EndRoleCut(end_role)
    };
    ReplyEvent::new_reply(
        reply_route,
        // TODO set algo and serialization
        SelfAddressing::Blake3_256,
        SerializationFormats::JSON,
    )
    .map_err(|e| Error::EventGenerationError(e.to_string()))
}
#[cfg(feature = "mailbox")]
pub fn exchange(
    receipient: &IdentifierPrefix,
    data: &KeriEvent<KeyEvent>,
    topic: ForwardTopic,
) -> Result<ExchangeMessage, Error> {
    use version::serialization_info::SerializationFormats;

    use crate::event_message::timestamped::Timestamped;

    let event = Timestamped::new(Exchange::Fwd {
        args: FwdArgs {
            recipient_id: receipient.clone(),
            topic,
        },
        to_forward: data.clone(),
    });

    KeriEvent::new(
        SerializationFormats::JSON,
        SelfAddressing::Blake3_256,
        event,
    )
    .map_err(|e| Error::EventGenerationError(e.to_string()))
}
