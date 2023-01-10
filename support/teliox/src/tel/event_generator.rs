use keri::{
    event::{sections::seal::EventSeal, SerializationFormats},
    prefix::IdentifierPrefix,
    sai::{derivation::SelfAddressing, SelfAddressingPrefix},
};

use crate::{
    error::Error,
    event::{
        manager_event::{Config, Inc, ManagerEventType, ManagerTelEvent, Rot},
        vc_event::{Issuance, Revocation, VCEvent, VCEventType},
        Event,
    },
    state::ManagerTelState,
};

pub fn make_inception_event(
    issuer_prefix: IdentifierPrefix,
    config: Vec<Config>,
    backer_threshold: u64,
    backers: Vec<IdentifierPrefix>,
    derivation: Option<&SelfAddressing>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let event_type = Inc {
        issuer_id: issuer_prefix,
        config,
        backer_threshold,
        backers,
    };

    Ok(Event::Management(
        event_type.incept_self_addressing(
            &derivation.unwrap_or(&SelfAddressing::Blake3_256),
            serialization_format
                .unwrap_or(&SerializationFormats::JSON)
                .to_owned(),
        )?,
    ))
}

pub fn make_rotation_event(
    state: &ManagerTelState,
    ba: &[IdentifierPrefix],
    br: &[IdentifierPrefix],
    derivation: Option<&SelfAddressing>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let rot_data = Rot {
        prev_event: derivation
            .unwrap_or(&SelfAddressing::Blake3_256)
            .derive(&state.last),
        backers_to_add: ba.to_vec(),
        backers_to_remove: br.to_vec(),
    };
    Ok(Event::Management(ManagerTelEvent::new(
        &state.prefix,
        state.sn + 1,
        ManagerEventType::Vrt(rot_data),
        serialization_format
            .unwrap_or(&SerializationFormats::JSON)
            .to_owned(),
    )?))
}

pub fn make_issuance_event(
    state: &ManagerTelState,
    vc_hash: SelfAddressingPrefix,
    derivation: Option<&SelfAddressing>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let registry_anchor = EventSeal {
        prefix: state.prefix.clone(),
        sn: state.sn,
        event_digest: derivation
            .unwrap_or(&SelfAddressing::Blake3_256)
            .derive(&state.last),
    };
    let iss = VCEventType::Bis(Issuance::new(state.issuer.clone(), registry_anchor));
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash);
    Ok(Event::Vc(VCEvent::new(
        vc_prefix.clone(),
        0,
        iss,
        )
        .to_message(serialization_format.unwrap_or(&SerializationFormats::JSON).clone(), derivation.unwrap_or(&SelfAddressing::Blake3_256).clone())?))
}

pub fn make_revoke_event(
    vc_hash: &SelfAddressingPrefix,
    last_vc_event_hash: SelfAddressingPrefix,
    state: &ManagerTelState,
    derivation: Option<&SelfAddressing>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let registry_anchor = EventSeal {
        prefix: state.prefix.to_owned(),
        sn: state.sn,
        event_digest: derivation
            .unwrap_or(&SelfAddressing::Blake3_256)
            .derive(&state.last),
    };
    let rev = VCEventType::Brv(Revocation {
        prev_event_hash: last_vc_event_hash,
        registry_anchor: Some(registry_anchor),
    });
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());

    Ok(Event::Vc(VCEvent::new(
        vc_prefix.clone(),
        state.sn + 1,
        rev,
        )
        .to_message(serialization_format.unwrap_or(&SerializationFormats::JSON).clone(), derivation.unwrap_or(&SelfAddressing::Blake3_256).clone())?))
}
