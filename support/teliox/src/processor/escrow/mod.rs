use std::{sync::Arc, time::Duration};

use keri_core::{database::EventDatabase, processor::event_storage::EventStorage};

use crate::{
    database::{TelEscrowDatabase, TelEventDatabase},
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

pub fn default_escrow_bus<
    D: TelEventDatabase + Send + Sync + 'static,
    K: EventDatabase + Send + Sync + 'static,
    E: TelEscrowDatabase + 'static,
>(
    tel_storage: Arc<D>,
    kel_storage: Arc<EventStorage<K>>,
    tel_escrow_db: E,
) -> Result<
    (
        TelNotificationBus,
        Arc<MissingIssuerEscrow<D, K, E>>,
        Arc<OutOfOrderEscrow<D, K, E>>,
        Arc<MissingRegistryEscrow<D, K, E>>,
    ),
    Error,
> {
    let escrow_db = Arc::new(tel_escrow_db);

    let out_of_order_escrow = Arc::new(OutOfOrderEscrow::new(
        tel_storage.clone(),
        kel_storage.clone(),
        escrow_db.clone(),
        Duration::from_secs(100),
    ));
    let missing_registry_escrow = Arc::new(MissingRegistryEscrow::new(
        tel_storage.clone(),
        kel_storage.clone(),
        escrow_db.clone(),
        Duration::from_secs(100),
    ));
    let tel_bus = TelNotificationBus::new();

    let missing_issuer_escrow = Arc::new(MissingIssuerEscrow::new(
        tel_storage.clone(),
        escrow_db,
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
