use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::{Context, Result};
use clap::Parser;
use figment::{
    providers::{Env, Format, Serialized, Yaml},
    Figment,
};
use keri_core::{
    oobi::{LocationScheme, Scheme},
    prefix::{CesrPrimitive, IdentifierPrefix},
};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DurationSeconds};
use tracing::info;
use url::Url;
use witness::{WitnessEscrowConfig, WitnessListener};

#[derive(Deserialize)]
pub struct Config {
    db_path: PathBuf,

    /// Public URL used to advertise itself to other actors using OOBI.
    public_url: Url,

    /// HTTP Listen port
    http_port: u16,

    /// Optional admin port hosting `/metrics`, `/health` and `/info`. Bound
    /// to [`Self::admin_bind`] (default loopback) so the metrics surface
    /// stays off the public network unless an operator explicitly opens it.
    /// `None` disables the admin listener entirely.
    #[serde(default)]
    admin_port: Option<u16>,

    /// Bind address for the admin listener. Defaults to `127.0.0.1` —
    /// switch to `0.0.0.0` (and firewall the port) only when the scrape
    /// target is on a different host than the witness.
    #[serde(default)]
    admin_bind: Option<String>,

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

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    admin_port: Option<u16>,

    #[arg(long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    admin_bind: Option<String>,

    #[arg(short = 's', long)]
    #[serde(skip_serializing_if = "Option::is_none")]
    seed: Option<String>,
}

const ENV_PREFIX: &str = "WITNESS_";

#[actix_web::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    info!(config_file = %args.config_file, "Loading configuration");

    let cfg = Figment::new()
        .merge(Yaml::file(args.config_file.clone()))
        .merge(Env::prefixed(ENV_PREFIX))
        .merge(Serialized::defaults(args))
        .extract::<Config>()
        .context("Failed to load config")?;

    let witness_listener = WitnessListener::setup_with_redb(
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

    info!(
        witness_id = %witness_listener.get_prefix().to_str(),
        port = cfg.http_port,
        oobi = %serde_json::to_string(&witness_loc_scheme).unwrap(),
        "Witness started",
    );

    // Bring up the admin listener first so operators can scrape `/metrics`
    // and `/health` even if the public port is firewalled or slow to come
    // up. Run as a detached background task: a failure to bind the admin
    // port is logged but does not take down the witness — losing metrics
    // is strictly less bad than dropping public traffic.
    if let Some(admin_port) = cfg.admin_port {
        let admin_bind = cfg
            .admin_bind
            .clone()
            .unwrap_or_else(|| "127.0.0.1".to_string());
        info!(bind = %admin_bind, port = admin_port, "Witness admin listener");
        let admin_handle = witness_listener.listen_admin((admin_bind.as_str(), admin_port));
        actix_web::rt::spawn(async move {
            if let Err(e) = admin_handle.await {
                tracing::error!(error = %e, "Admin listener exited with error");
            }
        });
    } else {
        info!("Witness admin listener disabled (no admin_port configured)");
    }

    let http_handle = witness_listener.listen_http((Ipv4Addr::UNSPECIFIED, cfg.http_port));
    http_handle.await?;

    Ok(())
}
