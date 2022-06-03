use std::path::PathBuf;

use anyhow::{anyhow, Result};
use figment::{
    providers::{Format, Json},
    Figment,
};
use keri::{oobi::LocationScheme, prefix::Prefix};
use serde::Deserialize;
use structopt::StructOpt;

use crate::watcher_data::WatcherListener;

mod watcher_data;

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
async fn main() -> Result<()> {
    let Opts { config_file } = Opts::from_args();

    let WatcherConfig {
        db_path,
        public_address,
        http_host,
        http_port,
        seed,
        initial_oobis,
    } = Figment::new().join(Json::file(config_file)).extract()
        .map_err(|_e| anyhow!("Improper `config.json` structure. Should contain fields: `db_path`, `http_host`, `http_port`. Set config file path with -c option."))?;

    let http_address = format!("http://{}:{}", http_host, http_port);

    let mut oobi_path = db_path.clone();
    oobi_path.push("oobi");
    let mut event_path = db_path.clone();
    event_path.push("events");

    let watcher_listener = WatcherListener::setup(
        url::Url::parse(&http_address).unwrap(),
        public_address,
        oobi_path.as_path(),
        event_path.as_path(),
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
