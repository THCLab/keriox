use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
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
use serde_with::{serde_as, DurationSeconds};
use url::Url;
use witness::{WitnessEscrowConfig, WitnessListener};

#[derive(Deserialize)]
pub struct Config {
    db_path: PathBuf,

    /// Public URL used to advertise itself to other actors using OOBI.
    public_url: Url,

    /// HTTP Listen port
    http_port: u16,

    /// Witness keypair seed
    seed: Option<String>,

    /// Time after which an escrowed event is considered stale.
    #[serde(default, deserialize_with = "deserialize_escrow_config")]
    escrow_timeout: WitnessEscrowConfig,
}

#[serde_as]
#[derive(Deserialize)]
struct PartialEscrowConfig {
    #[serde_as(as = "Option<DurationSeconds>")]
    default_timeout: Option<Duration>,

    #[serde_as(as = "Option<DurationSeconds>")]
    partially_signed_timeout: Option<Duration>,

    #[serde_as(as = "Option<DurationSeconds>")]
    out_of_order_timeout: Option<Duration>,

    #[serde_as(as = "Option<DurationSeconds>")]
    delegation_timeout: Option<Duration>,
}

fn deserialize_escrow_config<'de, D>(deserializer: D) -> Result<WitnessEscrowConfig, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let config = PartialEscrowConfig::deserialize(deserializer)?;
    Ok(WitnessEscrowConfig {
        partially_signed_timeout: config
            .partially_signed_timeout
            .or(config.default_timeout)
            .unwrap_or(WitnessEscrowConfig::default().partially_signed_timeout),
        out_of_order_timeout: config
            .out_of_order_timeout
            .or(config.default_timeout)
            .unwrap_or(WitnessEscrowConfig::default().out_of_order_timeout),
        delegation_timeout: config
            .delegation_timeout
            .or(config.default_timeout)
            .unwrap_or(WitnessEscrowConfig::default().delegation_timeout),
    })
}

#[derive(Debug, Parser, Serialize)]
#[command(author, version, about)]
struct Args {
    #[arg(short = 'c', long, default_value = "./witness.yml")]
    config_file: String,

    #[arg(short = 'd', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    db_path: Option<PathBuf>,

    #[arg(short = 'u', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    public_url: Option<Url>,

    #[arg(short = 'p', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    http_port: Option<u16>,

    #[arg(short = 's', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<String>,
}

const ENV_PREFIX: &str = "WITNESS_";

#[actix_web::main]
async fn main() -> Result<()> {
    // std::env::set_var("RUST_LOG", "debug");
    // std::env::set_var("RUST_BACKTRACE", "1");
    // env_logger::init();

    let args = Args::parse();

    println!("Using config file {:?}", args.config_file);
    println!("Using environment prefix: {:?}", ENV_PREFIX);

    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Env::prefixed(ENV_PREFIX))
        .merge(Serialized::defaults(args))
        .extract::<Config>()
        .context("Failed to load config")?;

    let witness_listener = WitnessListener::setup(
        cfg.public_url.clone(),
        cfg.db_path.as_path(),
        cfg.seed,
        cfg.escrow_timeout,
    )?;

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
