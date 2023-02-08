use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use keri::{
    oobi::{LocationScheme, Scheme},
    prefix::{CesrPrimitive, IdentifierPrefix},
};
use serde::{Deserialize, Serialize};
use url::Url;
use witness::WitnessListener;

#[serde_with::serde_as]
#[derive(Deserialize)]
pub struct Config {
    db_path: PathBuf,

    /// Public URL used to advertise itself to other actors using OOBI.
    public_url: Url,

    /// HTTP Listen port
    http_port: u16,

    /// Witness keypair seed
    seed: Option<String>,

    /// Time after which an escrowed event is considered stale (in seconds).
    #[serde_as(as = "serde_with::DurationSeconds")]
    escrow_timeout: Duration,
}

#[derive(Debug, Parser, Serialize)]
#[command(author, version, about)]
struct Args {
    #[arg(short = 'c', long, default_value = "./witness.yml")]
    config_file: String,

    #[arg(short = 'd', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    db_path: Option<PathBuf>,
}

#[actix_web::main]
async fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let args = Args::parse();
    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Env::prefixed("WITNESS_"))
        .merge(Serialized::defaults(args))
        .extract::<Config>()?;

    let witness_listener = WitnessListener::setup(
        cfg.public_url.clone(),
        cfg.db_path.as_path(),
        cfg.seed,
        cfg.escrow_timeout,
    )
    .unwrap();

    let witness_id = IdentifierPrefix::Basic(witness_listener.get_prefix());
    let witness_loc_scheme = LocationScheme {
        eid: witness_id.clone(),
        scheme: Scheme::Http,
        url: cfg.public_url.clone(),
    };

    println!(
        "\nWitness {} is listening on port {}",
        witness_listener.get_prefix().to_str(),
        cfg.http_port,
    );
    println!(
        "Witness's oobi: {}",
        serde_json::to_string(&witness_loc_scheme).unwrap()
    );

    let http_handle = witness_listener.listen_http((Ipv4Addr::UNSPECIFIED, cfg.http_port));
    http_handle.await?;

    Ok(())
}
