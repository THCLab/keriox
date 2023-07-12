use std::path::PathBuf;

use keri::{
    oobi::LocationScheme,
    processor::escrow::EscrowConfig,
    transport::{default::DefaultTransport, Transport},
};
use teliox::transport::{GeneralTelTransport, TelTransport};

pub struct ControllerConfig {
    pub db_path: PathBuf,
    pub initial_oobis: Vec<LocationScheme>,
    pub escrow_config: EscrowConfig,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn GeneralTelTransport + Send + Sync>,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            db_path: PathBuf::from("db"),
            initial_oobis: vec![],
            escrow_config: EscrowConfig::default(),
            transport: Box::new(DefaultTransport::new()),
            tel_transport: Box::new(TelTransport)
        }
    }
}
