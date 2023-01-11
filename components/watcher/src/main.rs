use std::path::PathBuf;

use figment::{
    providers::{Format, Json},
    Figment,
};
use keri::{
    event_parsing::primitives::CesrPrimitive,
    oobi::{LocationScheme, Scheme},
    prefix::IdentifierPrefix,
};
use serde::Deserialize;
use structopt::StructOpt;
use watcher::WatcherListener;

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
    let watcher_url = url::Url::parse(&http_address).unwrap();

    let watcher_listener =
        WatcherListener::setup(watcher_url.clone(), public_address, &db_path, seed).unwrap();

    // Resolve oobi to know how to find witness
    watcher_listener
        .resolve_initial_oobis(&initial_oobis)
        .await
        .unwrap();
    let watcher_id = watcher_listener.get_prefix();
    let watcher_loc_scheme = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: Scheme::Http,
        url: watcher_url,
    };

    println!(
        "Watcher {} is listening on {}",
        watcher_id.to_str(),
        http_address,
    );
    println!(
        "Watcher's oobi: {}",
        serde_json::to_string(&watcher_loc_scheme).unwrap()
    );

    watcher_listener
        .listen_http(url::Url::parse(&http_address).unwrap())
        .await?;

    Ok(())
}
