use keri_core::{event::sections::seal::EventSeal, prefix::IdentifierPrefix};
use said::version::format::SerializationFormats;
use said::{derivation::HashFunction, derivation::HashFunctionCode, SelfAddressingIdentifier};

use crate::{
    error::Error,
    event::{
        manager_event::{Config, Inc, ManagerEventType, ManagerTelEvent, Rot},
        vc_event::{Issuance, Revocation, SimpleIssuance, SimpleRevocation, VCEvent, VCEventType},
        Event,
    },
    state::ManagerTelState,
};

pub fn make_inception_event(
    issuer_prefix: IdentifierPrefix,
    config: Vec<Config>,
    backer_threshold: u64,
    backers: Vec<IdentifierPrefix>,
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let event_type = Inc {
        issuer_id: issuer_prefix,
        config,
        backer_threshold,
        backers,
    };

    Ok(Event::Management(
        event_type
            .incept_self_addressing(
                &HashFunction::from(
                    derivation
                        .unwrap_or(&HashFunctionCode::Blake3_256)
                        .to_owned(),
                ),
                serialization_format
                    .unwrap_or(&SerializationFormats::JSON)
                    .to_owned(),
            )?
            .to_message(
                *serialization_format.unwrap_or(&SerializationFormats::JSON),
                derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
            )?,
    ))
}

pub fn make_rotation_event(
    state: &ManagerTelState,
    ba: &[IdentifierPrefix],
    br: &[IdentifierPrefix],
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let rot_data = Rot {
        prev_event: state.last.clone(),
        backers_to_add: ba.to_vec(),
        backers_to_remove: br.to_vec(),
    };
    Ok(Event::Management(
        ManagerTelEvent::new(&state.prefix, state.sn + 1, ManagerEventType::Vrt(rot_data))
            .to_message(
                serialization_format
                    .unwrap_or(&SerializationFormats::JSON)
                    .to_owned(),
                derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
            )?,
    ))
}

pub fn make_simple_issuance_event(
    registry_id: IdentifierPrefix,
    vc_hash: SelfAddressingIdentifier,
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let iss = VCEventType::Iss(SimpleIssuance { registry_id });
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash);
    Ok(Event::Vc(VCEvent::new(vc_prefix, 0, iss).to_message(
        *serialization_format.unwrap_or(&SerializationFormats::JSON),
        derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
    )?))
}

pub fn make_issuance_event(
    state: &ManagerTelState,
    vc_hash: SelfAddressingIdentifier,
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let registry_anchor = EventSeal {
        prefix: state.prefix.clone(),
        sn: state.sn,
        event_digest: state.last.clone(),
    };
    let iss = VCEventType::Bis(Issuance::new(state.issuer.clone(), registry_anchor));
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash);
    Ok(Event::Vc(VCEvent::new(vc_prefix, 0, iss).to_message(
        *serialization_format.unwrap_or(&SerializationFormats::JSON),
        derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
    )?))
}

pub fn make_simple_revoke_event(
    vc_hash: &SelfAddressingIdentifier,
    last_vc_event_hash: SelfAddressingIdentifier,
    state: &ManagerTelState,
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let rev = VCEventType::Rev(SimpleRevocation {
        registry_id: state.prefix.clone(),
        prev_event_hash: last_vc_event_hash,
    });
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());

    Ok(Event::Vc(
        VCEvent::new(vc_prefix, state.sn + 1, rev).to_message(
            *serialization_format.unwrap_or(&SerializationFormats::JSON),
            derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
        )?,
    ))
}

pub fn make_revoke_event(
    vc_hash: &SelfAddressingIdentifier,
    last_vc_event_hash: SelfAddressingIdentifier,
    state: &ManagerTelState,
    derivation: Option<&HashFunctionCode>,
    serialization_format: Option<&SerializationFormats>,
) -> Result<Event, Error> {
    let registry_anchor = EventSeal {
        prefix: state.prefix.to_owned(),
        sn: state.sn,
        event_digest: state.last.clone(),
    };
    let rev = VCEventType::Brv(Revocation {
        prev_event_hash: last_vc_event_hash,
        registry_anchor: Some(registry_anchor),
    });
    let vc_prefix = IdentifierPrefix::SelfAddressing(vc_hash.to_owned());

    Ok(Event::Vc(
        VCEvent::new(vc_prefix, state.sn + 1, rev).to_message(
            *serialization_format.unwrap_or(&SerializationFormats::JSON),
            derivation.unwrap_or(&HashFunctionCode::Blake3_256).clone(),
        )?,
    ))
}
