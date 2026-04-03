use std::{path::PathBuf, time::Duration};

use keri_core::{
    processor::escrow::EscrowConfig,
    transport::{default::DefaultTransport, Transport},
};

use crate::transport::{HttpTelTransport, WatcherTelTransport};

pub struct WatcherConfig {
    pub public_address: url::Url,
    pub db_path: PathBuf,
    pub priv_key: Option<String>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn WatcherTelTransport + Send + Sync>,
    pub tel_storage_path: PathBuf,
    pub escrow_config: EscrowConfig,
    /// Interval between background witness polling cycles.
    /// Set to Duration::ZERO to disable polling.
    pub poll_interval: Duration,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            public_address: url::Url::parse("http://localhost:3236").unwrap(),
            db_path: PathBuf::from("db"),
            priv_key: None,
            transport: Box::new(DefaultTransport::new()),
            tel_transport: Box::new(HttpTelTransport),
            tel_storage_path: PathBuf::from("tel_storage"),
            escrow_config: EscrowConfig::default(),
            poll_interval: Duration::from_secs(30),
        }
    }
}
