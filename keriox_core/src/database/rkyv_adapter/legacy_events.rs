//! The stored (rkyv-archived) layout of key events before rotations had a
//! configuration traits field `c`, kept to read databases written by
//! earlier versions once, when they are migrated. Field order and types
//! must stay exactly as they were: the archived layout depends on them.

use rkyv::{rancor::Failure, util::AlignedVec};
use said::version::SerializationInfo;

use super::{said_wrapper::SaidValue, serialization_info_wrapper::SerializationInfoDef};
use crate::{
    event::{
        event_data::{
            DelegatedInceptionEvent, EventData, InceptionEvent, InteractionEvent, RotationEvent,
        },
        sections::{seal::Seal, KeyConfig, RotationWitnessConfig},
        KeyEvent,
    },
    event_message::{msg::KeriEvent, EventTypeTag},
    prefix::IdentifierPrefix,
};

/// Version of the stored key event layout written by this keriox: 1 added
/// `c` to rotations. Databases without a version predate it.
pub(crate) const EVENTS_LAYOUT: u64 = 1;

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct RotationEventV0 {
    previous_event_hash: SaidValue,
    key_config: KeyConfig,
    witness_config: RotationWitnessConfig,
    data: Vec<Seal>,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) enum EventDataV0 {
    Dip(DelegatedInceptionEvent),
    Icp(InceptionEvent),
    Rot(RotationEventV0),
    Ixn(InteractionEvent),
    Drt(RotationEventV0),
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct KeyEventV0 {
    prefix: IdentifierPrefix,
    sn: u64,
    event_data: EventDataV0,
}

#[derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
pub(crate) struct KeriEventV0 {
    #[rkyv(with = SerializationInfoDef)]
    serialization_info: SerializationInfo,
    event_type: EventTypeTag,
    digest: Option<SaidValue>,
    data: KeyEventV0,
}

impl From<RotationEventV0> for RotationEvent {
    fn from(rot: RotationEventV0) -> Self {
        RotationEvent::new(
            rot.previous_event_hash.said,
            rot.key_config,
            rot.witness_config,
            rot.data,
        )
    }
}

impl From<KeriEventV0> for KeriEvent<KeyEvent> {
    fn from(event: KeriEventV0) -> Self {
        let event_data = match event.data.event_data {
            EventDataV0::Dip(dip) => EventData::Dip(dip),
            EventDataV0::Icp(icp) => EventData::Icp(icp),
            EventDataV0::Rot(rot) => EventData::Rot(rot.into()),
            EventDataV0::Ixn(ixn) => EventData::Ixn(ixn),
            EventDataV0::Drt(drt) => EventData::Drt(drt.into()),
        };
        KeriEvent {
            serialization_info: event.serialization_info,
            event_type: event.event_type,
            digest: event.digest,
            data: KeyEvent::new(event.data.prefix, event.data.sn, event_data),
        }
    }
}

/// Re-encodes a key event stored in the layout before version 1.
pub(crate) fn upgrade_event(bytes: &[u8]) -> Result<AlignedVec, String> {
    let mut aligned = AlignedVec::<16>::new();
    aligned.extend_from_slice(bytes);
    let old = rkyv::from_bytes::<KeriEventV0, Failure>(&aligned)
        .map_err(|_| "a stored key event is in neither the old nor the new layout".to_string())?;
    rkyv::to_bytes::<rkyv::rancor::Error>(&KeriEvent::<KeyEvent>::from(old))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The old layout of `event`, as an earlier keriox stored it. Only
    /// rotations without `c` existed then.
    pub(crate) fn old_layout(event: &KeriEvent<KeyEvent>) -> AlignedVec {
        let rot = |rot: &RotationEvent| RotationEventV0 {
            previous_event_hash: rot.previous_event_hash().clone().into(),
            key_config: rot.key_config.clone(),
            witness_config: rot.witness_config.clone(),
            data: rot.data.clone(),
        };
        let event_data = match &event.data.event_data {
            EventData::Dip(dip) => EventDataV0::Dip(dip.clone()),
            EventData::Icp(icp) => EventDataV0::Icp(icp.clone()),
            EventData::Rot(r) => EventDataV0::Rot(rot(r)),
            EventData::Ixn(ixn) => EventDataV0::Ixn(ixn.clone()),
            EventData::Drt(r) => EventDataV0::Drt(rot(r)),
        };
        let old = KeriEventV0 {
            serialization_info: event.serialization_info.clone(),
            event_type: event.event_type.clone(),
            digest: event.digest.clone(),
            data: KeyEventV0 {
                prefix: event.data.prefix.clone(),
                sn: event.data.sn,
                event_data,
            },
        };
        rkyv::to_bytes::<rkyv::rancor::Error>(&old).unwrap()
    }
}
