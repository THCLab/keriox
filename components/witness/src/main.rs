use std::path::PathBuf;

use anyhow::{anyhow, Result};
use figment::{
    providers::{Format, Json},
    Figment,
};
use keri::event_parsing::primitives::CesrPrimitive;
use serde::Deserialize;
use structopt::StructOpt;
use witness::WitnessListener;

#[derive(Deserialize)]
pub struct WitnessConfig {
    db_path: PathBuf,
    public_address: Option<String>,
    /// Witness listen host.
    http_host: String,
    /// Witness listen port.
    http_port: u16,
    /// Witness keypair seed
    seed: Option<String>,
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long, default_value = "./witness.json")]
    config_file: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    std::env::set_var("RUST_LOG", "debug");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();
    let Opts { config_file } = Opts::from_args();

    let WitnessConfig {
        db_path,
        public_address,
        http_host,
        http_port,
        seed,
    } = Figment::new().join(Json::file(config_file))
        .extract()
        .map_err(|_e| anyhow!("Improper `config.json` structure. Should contain fields: `db_path`, `http_host`, `http_port`. Set config file path with -c option."))?;

    let http_address = format!("http://{}:{}", http_host, http_port);

    let witness_listener = WitnessListener::setup(
        url::Url::parse(&http_address).unwrap(),
        public_address,
        db_path.as_path(),
        seed,
    )
    .unwrap();

    println!(
        "\nWitness {} is listening on {}",
        witness_listener.get_prefix().to_str(),
        http_address,
    );

    let http_handle = witness_listener.listen_http(url::Url::parse(&http_address).unwrap());
    http_handle.await?;

    Ok(())
}
