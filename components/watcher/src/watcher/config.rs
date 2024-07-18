use std::path::PathBuf;

use keri_core::{
    processor::escrow::EscrowConfig,
    transport::{default::DefaultTransport, Transport},
};
use teliox::transport::{GeneralTelTransport, TelTransport};

pub struct WatcherConfig {
    pub public_address: url::Url,
    pub db_path: PathBuf,
    pub priv_key: Option<String>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn GeneralTelTransport + Send + Sync>,
    pub escrow_config: EscrowConfig,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            public_address: url::Url::parse("http://localhost:3236").unwrap(),
            db_path: PathBuf::from("db"),
            priv_key: None,
            transport: Box::new(DefaultTransport::new()),
            tel_transport: Box::new(TelTransport),
            escrow_config: EscrowConfig::default(),
        }
    }
}
