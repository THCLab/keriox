use std::path::PathBuf;

use figment::{
    providers::{Format, Json},
    Figment,
};
use keri::{oobi::LocationScheme, prefix::Prefix};
use serde::Deserialize;
use structopt::StructOpt;

use crate::watcher_listener::WatcherListener;

mod watcher;
mod watcher_listener;

#[derive(Deserialize)]
pub struct WatcherConfig {
    db_path: PathBuf,
    public_address: Option<String>,
    /// Witness listen host.
    http_host: String,
    /// Witness listen port.
    http_port: u16,
    /// Witness private key
    seed: Option<String>,
    initial_oobis: Vec<LocationScheme>,
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long, default_value = "./watcher.json")]
    config_file: String,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Opts { config_file } = Opts::from_args();

    let WatcherConfig {
        db_path,
        public_address,
        http_host,
        http_port,
        seed,
        initial_oobis,
    } = Figment::new().join(Json::file(config_file)).extract()?;

    let http_address = format!("http://{}:{}", http_host, http_port);

    let watcher_listener = WatcherListener::setup(
        url::Url::parse(&http_address).unwrap(),
        public_address,
        &db_path,
        seed,
    )
    .unwrap();

    // Resolve oobi to know how to find witness
    watcher_listener
        .resolve_initial_oobis(&initial_oobis)
        .await
        .unwrap();

    println!(
        "Watcher {} is listening on {}",
        watcher_listener.get_prefix().to_str(),
        http_address,
    );

    watcher_listener
        .listen_http(url::Url::parse(&http_address).unwrap())
        .await?;

    Ok(())
}
