use std::{sync::Arc, time::Duration};

use keri::{processor::event_storage::EventStorage, database::escrow::EscrowDb};

use crate::error::Error;

use self::{out_of_order::OutOfOrderEscrow, missing_registry::MissingRegistryEscrow, missing_issuer::MissingIssuerEscrow};

use super::notification::{TelNotificationBus, TelNotificationKind};

pub mod missing_issuer;
pub mod missing_registry;
pub mod out_of_order;

pub fn default_escrow_bus(tel_storage: Arc<super::storage::TelEventStorage>, kel_storage: Arc<EventStorage>, tel_escrow_db: Arc<EscrowDb>) -> Result<(TelNotificationBus, Arc<MissingIssuerEscrow>, Arc<OutOfOrderEscrow>, Arc<MissingRegistryEscrow>), Error> {
	let out_of_order_escrow = Arc::new(OutOfOrderEscrow::new(tel_storage.clone(), kel_storage.clone(), tel_escrow_db.clone(), Duration::from_secs(100)));
	let missing_registry_escrow = Arc::new(MissingRegistryEscrow::new(tel_storage.clone(), kel_storage.clone(), tel_escrow_db.clone(), Duration::from_secs(100)));
	let tel_bus = TelNotificationBus::new();

	let missing_issuer_escrow = Arc::new(MissingIssuerEscrow::new(
		tel_storage.clone(),
		tel_escrow_db,
		Duration::from_secs(100),
		kel_storage.clone(),
		tel_bus.clone(),
	));

	tel_bus.register_observer(out_of_order_escrow.clone(), vec![TelNotificationKind::OutOfOrder, TelNotificationKind::TelEventAdded]).unwrap();
        tel_bus.register_observer(missing_registry_escrow.clone(), vec![TelNotificationKind::MissingRegistry, TelNotificationKind::TelEventAdded]).unwrap();
        tel_bus
            .register_observer(
                missing_issuer_escrow.clone(),
                vec![TelNotificationKind::MissingIssuer],
			).unwrap();
			Ok((tel_bus, missing_issuer_escrow, out_of_order_escrow, missing_registry_escrow))
}