use std::path::PathBuf;

use figment::{Figment, providers::{Json, Format}};
use keri::{oobi::LocationScheme, prefix::Prefix};
use serde::Deserialize;
use structopt::StructOpt;
use anyhow::{Result, anyhow};
use futures::future::join_all;

use crate::watcher_data::WatcherData;

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
    #[structopt(short = "c", long, default_value = "./src/bin/configs/watcher.json")]
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
        .map_err(|_e| anyhow!("Missing arguments: `db_path`, `http_host`, `http_port`. Set config file path with -c option."))?;

    let http_address = format!("http://{}:{}", http_host, http_port);

    let mut oobi_path = db_path.clone();
    oobi_path.push("oobi");
    let mut event_path = db_path.clone();
    event_path.push("events");

    let wit_data = WatcherData::setup(
        url::Url::parse(&http_address).unwrap(),
        public_address,
        oobi_path.as_path(),
        event_path.as_path(),
        seed,
    )
    .unwrap();
    let wit_prefix = wit_data.controller.prefix.clone();

    // Resolve oobi to know how to find witness
    join_all(
        initial_oobis
            .iter()
            .map(|lc| wit_data.resolve_loc_scheme(lc)),
    )
    .await;

    println!(
        "Watcher {} is listening on {}",
        wit_prefix.to_str(),
        http_address,
    );

    wit_data
        .listen_http(url::Url::parse(&http_address).unwrap())
        .await?;

    Ok(())
}
