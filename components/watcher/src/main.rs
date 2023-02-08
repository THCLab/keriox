use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use keri::{
    oobi::{LocationScheme, Scheme},
    prefix::{CesrPrimitive, IdentifierPrefix},
    transport::default::DefaultTransport,
};
use serde::{Deserialize, Serialize};
use url::Url;
use watcher::{WatcherConfig, WatcherListener};

#[serde_with::serde_as]
#[derive(Deserialize)]
pub struct Config {
    db_path: PathBuf,

    /// Public URL used to advertise itself to other actors using OOBI.
    public_url: Url,

    /// HTTP listen port.
    http_port: u16,

    /// Witness private key
    seed: Option<String>,

    initial_oobis: Vec<LocationScheme>,

    /// Time after which an escrowed event is considered stale (in seconds).
    #[serde_as(as = "serde_with::DurationSeconds")]
    escrow_timeout: Duration,
}

#[derive(Debug, Parser, Serialize)]
struct Args {
    #[arg(short = 'c', long, default_value = "./watcher.yml")]
    config_file: String,

    #[arg(short = 'd', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    db_path: Option<PathBuf>,
}

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Env::prefixed("WATCHER_"))
        .merge(Serialized::defaults(args))
        .extract::<Config>()?;

    let watcher_listener = WatcherListener::new(WatcherConfig {
        public_address: cfg.public_url.clone(),
        db_path: cfg.db_path.clone(),
        priv_key: cfg.seed,
        transport: Box::new(DefaultTransport::new()),
        escrow_timeout: cfg.escrow_timeout,
    })
    .unwrap();

    // Resolve oobi to know how to find witness
    watcher_listener
        .resolve_initial_oobis(&cfg.initial_oobis)
        .await
        .unwrap();
    let watcher_id = watcher_listener.get_prefix();
    let watcher_loc_scheme = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: Scheme::Http,
        url: cfg.public_url.clone(),
    };

    println!(
        "Watcher {} is listening on port {}",
        watcher_id.to_str(),
        cfg.http_port,
    );
    println!(
        "Watcher's oobi: {}",
        serde_json::to_string(&watcher_loc_scheme).unwrap()
    );

    watcher_listener
        .listen_http((Ipv4Addr::UNSPECIFIED, cfg.http_port))
        .await?;

    Ok(())
}
