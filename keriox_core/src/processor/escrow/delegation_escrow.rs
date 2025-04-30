use std::{sync::Arc, time::Duration};

use said::SelfAddressingIdentifier;

use crate::{
    actor::prelude::EventStorage,
    database::{
        redb::{escrow_database::SnKeyDatabase, RedbDatabase},
        EventDatabase,
    },
    error::Error,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal, SourceSeal},
    },
    event_message::signed_event_message::SignedEventMessage,
    prefix::IdentifierPrefix,
    processor::{
        notification::{Notification, NotificationBus, Notifier},
        validator::EventValidator,
    },
};

use super::maybe_out_of_order_escrow::SnKeyEscrow;

/// Stores delegated events until delegating event is provided
pub struct DelegationEscrow<D: EventDatabase> {
    db: Arc<D>,
    // Key of this escrow is (delegator's identifier, delegator's event sn if available).
    pub delegation_escrow: SnKeyEscrow,
}

impl DelegationEscrow<RedbDatabase> {
    pub fn new(
        db: Arc<RedbDatabase>,
        _duration: Duration,
    ) -> Self {
        let escrow_db = SnKeyEscrow::new(
            Arc::new(SnKeyDatabase::new(db.db.clone(), "delegation_escrow").unwrap()),
            db.log_db.clone(),
        );
        Self {
            db,
            delegation_escrow: escrow_db,
        }
    }

    pub fn get_event_by_sn_and_digest(
        &self,
        sn: u64,
        delegator_id: &IdentifierPrefix,
        event_digest: &SelfAddressingIdentifier,
    ) -> Option<SignedEventMessage> {
        self.delegation_escrow
            .get(delegator_id, sn)
            .ok()
            .and_then(|mut events| {
                events.find(|event| {
                    event.event_message.data.sn == sn
                        && event.event_message.digest().ok().as_ref() == Some(event_digest)
                })
            })
    }
}

impl Notifier for DelegationEscrow<RedbDatabase> {
    fn notify(&self, notification: &Notification, bus: &NotificationBus) -> Result<(), Error> {
        match notification {
            Notification::KeyEventAdded(ev_message) => {
                // delegator's prefix
                let id = ev_message.event_message.data.get_prefix();
                // get anchored data
                let anchored_data: Vec<Seal> = match &ev_message.event_message.data.event_data {
                    EventData::Icp(icp) => icp.data.clone(),
                    EventData::Rot(rot) => rot.data.clone(),
                    EventData::Ixn(ixn) => ixn.data.clone(),
                    EventData::Dip(dip) => dip.inception_data.data.clone(),
                    EventData::Drt(drt) => drt.data.clone(),
                };

                let seals: Vec<EventSeal> = anchored_data
                    .into_iter()
                    .filter_map(|seal| match seal {
                        Seal::Event(es) => Some(es),
                        _ => None,
                    })
                    .collect();
                if !seals.is_empty() {
                    let potential_delegator_seal = SourceSeal::new(
                        ev_message.event_message.data.get_sn(),
                        ev_message.event_message.digest()?,
                    );
                    self.process_delegation_events(bus, &id, seals, potential_delegator_seal)?;
                }
            }
            Notification::MissingDelegatingEvent(signed_event) => {
                // ignore events with no signatures
                if !signed_event.signatures.is_empty() {
                    let delegator_id = match &signed_event.event_message.data.event_data {
                        EventData::Dip(dip) => Ok(dip.delegator.clone()),
                        EventData::Drt(_drt) => {
                            let storage = EventStorage::new(self.db.clone());
                            storage
                                .get_state(&signed_event.event_message.data.get_prefix())
                                .ok_or(Error::MissingDelegatingEventError)?
                                .delegator
                                .ok_or(Error::MissingDelegatingEventError)
                        }
                        _ => {
                            // not delegated event
                            Err(Error::SemanticError("Not delegated event".to_string()))
                        }
                    }?;
                    let delegator_seal = signed_event.delegator_seal.clone();
                    let sn = if let Some(delegator_seal) = delegator_seal {
                        delegator_seal.sn
                    } else {
                        0
                    };
                    self.delegation_escrow
                        .insert_key_value(&delegator_id, sn, signed_event)?;
                }
            }
            _ => return Err(Error::SemanticError("Wrong notification".into())),
        }

        Ok(())
    }
}

impl DelegationEscrow<RedbDatabase> {
    pub fn process_delegation_events(
        &self,
        bus: &NotificationBus,
        delegator_id: &IdentifierPrefix,
        anchored_seals: Vec<EventSeal>,
        potential_delegator_seal: SourceSeal,
    ) -> Result<(), Error> {
        if let Ok(esc) = self.delegation_escrow.get_from_sn(delegator_id, 0) {
            for event in esc {
                let event_digest = event.event_message.digest()?;
                let seal = anchored_seals.iter().find(|seal| {
                    seal.event_digest() == event_digest
                        && seal.sn == event.event_message.data.get_sn()
                        && seal.prefix == event.event_message.data.get_prefix()
                });
                let delegated_event = match seal {
                    Some(_s) => SignedEventMessage {
                        delegator_seal: Some(potential_delegator_seal.clone()),
                        ..event.clone()
                    },
                    None => event.clone(),
                };
                let validator = EventValidator::new(self.db.clone());
                match validator.validate_event(&delegated_event) {
                    Ok(_) => {
                        // add to kel
                        let child_id = event.event_message.data.get_prefix();
                        self.db
                            .add_kel_finalized_event(delegated_event.clone(), &child_id)
                            .map_err(|_| Error::DbError)?;
                        // remove from escrow
                        self.delegation_escrow.remove(&event.event_message);
                        bus.notify(&Notification::KeyEventAdded(event))?;
                        // stop processing the escrow if kel was updated. It needs to start again.
                        break;
                    }
                    Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.delegation_escrow.remove(&event.event_message);
                    }
                    Err(Error::NotEnoughReceiptsError) => {
                        // remove from escrow
                        self.delegation_escrow.remove(&event.event_message);
                        bus.notify(&Notification::PartiallyWitnessed(delegated_event))?;
                    }
                    Err(_e) => (), // keep in escrow,
                }
            }
        };

        Ok(())
    }
}
