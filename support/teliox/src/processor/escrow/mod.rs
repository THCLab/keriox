use std::{sync::Arc, time::Duration};

use keri_core::{database::redb::RedbDatabase, processor::event_storage::EventStorage};

use crate::{
    database::{redb::RedbTelDatabase, EscrowDatabase},
    error::Error,
    processor::notification::TelNotificationKind,
};

use self::{
    missing_issuer::MissingIssuerEscrow, missing_registry::MissingRegistryEscrow,
    out_of_order::OutOfOrderEscrow,
};

use super::notification::TelNotificationBus;

pub mod missing_issuer;
pub mod missing_registry;
pub mod out_of_order;

pub fn default_escrow_bus(
    tel_storage: Arc<RedbTelDatabase>,
    kel_storage: Arc<EventStorage<RedbDatabase>>,
    tel_escrow_db: EscrowDatabase,
) -> Result<
    (
        TelNotificationBus,
        Arc<MissingIssuerEscrow<RedbTelDatabase>>,
        Arc<OutOfOrderEscrow<RedbTelDatabase>>,
        Arc<MissingRegistryEscrow<RedbTelDatabase>>,
    ),
    Error,
> {
    let out_of_order_escrow = Arc::new(OutOfOrderEscrow::new(
        tel_storage.clone(),
        kel_storage.clone(),
        &tel_escrow_db,
        Duration::from_secs(100),
    ));
    let missing_registry_escrow = Arc::new(MissingRegistryEscrow::new(
        tel_storage.clone(),
        kel_storage.clone(),
        &tel_escrow_db,
        Duration::from_secs(100),
    ));
    let tel_bus = TelNotificationBus::new();

    let missing_issuer_escrow = Arc::new(MissingIssuerEscrow::new(
        tel_storage.clone(),
        &tel_escrow_db,
        Duration::from_secs(100),
        kel_storage.clone(),
        tel_bus.clone(),
    ));

    tel_bus.register_observer(
        out_of_order_escrow.clone(),
        vec![
            TelNotificationKind::OutOfOrder,
            TelNotificationKind::TelEventAdded,
        ],
    )?;
    tel_bus.register_observer(
        missing_registry_escrow.clone(),
        vec![
            TelNotificationKind::MissingRegistry,
            TelNotificationKind::TelEventAdded,
        ],
    )?;
    tel_bus.register_observer(
        missing_issuer_escrow.clone(),
        vec![TelNotificationKind::MissingIssuer],
    )?;
    Ok((
        tel_bus,
        missing_issuer_escrow,
        out_of_order_escrow,
        missing_registry_escrow,
    ))
}
