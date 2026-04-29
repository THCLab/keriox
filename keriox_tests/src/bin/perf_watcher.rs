//! Performance harness for the watcher AID-verification flow.
//!
//! Boots N witnesses + 1 watcher in-process, creates M signing identifiers
//! (each anchored to K witnesses), then drives the watcher's HTTP API to
//! make it fetch each signer's KEL via one of that signer's witnesses. This
//! is the same network path a real client triggers when it asks the watcher
//! "verify an AID I've never seen": resolve OOBI → fetch KEL via witness.
//!
//! We deliberately drive the watcher through its public HTTP surface
//! (POST /resolve) instead of going through the full controller
//! `add_watcher`/`query_watchers` flow, which has a pre-existing hang in
//! HEAD's `query_updates` test that's unrelated to this perf work. The
//! HTTP path covers everything we instrumented:
//!   - watcher /resolve handler latency
//!   - watcher → witness HTTP request (shared client + pooling)
//!   - OOBI parsing/storage
//!   - KEL parsing/storage
//!
//! At the end the harness scrapes the watcher's `/metrics` endpoint so
//! the Prometheus histograms have observed values to show.
//!
//! Tunables (env vars):
//!   PERF_WITNESSES        default 5    total witnesses
//!   PERF_IDENTIFIERS      default 20   identifiers to create
//!   PERF_WITS_PER_ID      default 3    witnesses anchored per identifier
//!   PERF_BASE_PORT        default 4000 first witness port (watcher = base + 900)
//!   PERF_PARALLEL_VERIFY  default 1    verifier flows to run concurrently
//!   PERF_METRICS_DUMP     default /tmp/perf_watcher_metrics.txt
//!
//! Run: `cargo run --release -p keri-tests --bin perf_watcher`

use std::{
    net::Ipv4Addr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use actix_rt::time::sleep;
use anyhow::Result;
use futures::future::join_all;
use keri_controller::{
    config::ControllerConfig, controller::Controller, BasicPrefix, CryptoBox, EndRole,
    IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder, PrometheusHandle};
use tempfile::Builder;
use url::Url;
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

#[derive(Clone)]
struct WitnessHandle {
    id: BasicPrefix,
    oobi: LocationScheme,
}

#[derive(Clone)]
struct Signer {
    id: IdentifierPrefix,
    witnesses: Vec<WitnessHandle>,
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[actix_rt::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn,perf_watcher=info")),
        )
        .compact()
        .init();

    // Install the Prometheus recorder *here*, before any watcher/witness
    // listener tries to. Their internal install() calls will then return
    // None (global already set), and every histogram/counter still flows
    // into this single recorder. We render via this handle at the end.
    let metrics_handle: PrometheusHandle = install_prometheus_recorder();

    let n_witnesses = env_usize("PERF_WITNESSES", 5);
    let n_identifiers = env_usize("PERF_IDENTIFIERS", 20);
    let wits_per_id = env_usize("PERF_WITS_PER_ID", 3).min(n_witnesses);
    let base_port: u16 = env_usize("PERF_BASE_PORT", 4000) as u16;
    let parallel_verify = env_usize("PERF_PARALLEL_VERIFY", 1).max(1);
    let watcher_port = base_port + 900;

    println!(
        "perf_watcher config: witnesses={} identifiers={} wits_per_id={} parallel_verify={} base_port={}",
        n_witnesses, n_identifiers, wits_per_id, parallel_verify, base_port
    );

    // 1. Boot witnesses ------------------------------------------------------
    let mut witnesses: Vec<WitnessHandle> = Vec::with_capacity(n_witnesses);
    for i in 0..n_witnesses {
        let port = base_port + i as u16;
        let url = Url::parse(&format!("http://127.0.0.1:{}", port))?;
        let dir_path: PathBuf = Builder::new()
            .prefix("perf-wit-db")
            .tempdir()?
            .keep();
        let listener = Arc::new(WitnessListener::setup_with_redb(
            url.clone(),
            &dir_path,
            None,
            WitnessEscrowConfig::default(),
        )?);
        let id = listener.get_prefix();
        actix_rt::spawn(listener.listen_http((Ipv4Addr::UNSPECIFIED, port)));
        witnesses.push(WitnessHandle {
            id: id.clone(),
            oobi: LocationScheme {
                eid: IdentifierPrefix::Basic(id),
                scheme: keri_core::oobi::Scheme::Http,
                url,
            },
        });
    }

    // 2. Boot watcher --------------------------------------------------------
    let watcher_url = Url::parse(&format!("http://127.0.0.1:{}", watcher_port))?;
    let watcher_dir: PathBuf = Builder::new().prefix("perf-watcher-db").tempdir()?.keep();
    let watcher_tel_path = watcher_dir.join("tel_storage");
    let watcher_listener = WatcherListener::setup_with_redb(WatcherConfig {
        public_address: watcher_url.clone(),
        db_path: watcher_dir.clone(),
        tel_storage_path: watcher_tel_path,
        ..Default::default()
    })?;
    actix_rt::spawn(watcher_listener.listen_http((Ipv4Addr::UNSPECIFIED, watcher_port)));

    // Give servers a moment to bind.
    sleep(Duration::from_millis(200)).await;

    // 3. Create signing identifiers, anchored to K witnesses each ------------
    println!("creating {} identifiers...", n_identifiers);
    let mut signers = Vec::with_capacity(n_identifiers);
    let setup_start = Instant::now();
    for i in 0..n_identifiers {
        let assigned: Vec<&WitnessHandle> = witnesses
            .iter()
            .cycle()
            .skip(i)
            .take(wits_per_id)
            .collect();
        let signer = create_signer(i, &assigned).await?;
        signers.push(signer);
    }
    let setup_elapsed = setup_start.elapsed();
    println!(
        "identifier setup done in {:.2}s ({:.0}ms/id avg)",
        setup_elapsed.as_secs_f64(),
        setup_elapsed.as_millis() as f64 / n_identifiers as f64
    );

    // 4. Drive watcher /resolve for each signer, optionally in parallel -----
    println!("running verifier flow over {} identifiers...", n_identifiers);
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut latencies_ms: Vec<u128> = Vec::with_capacity(n_identifiers);
    let mut failures: Vec<String> = vec![];
    let verify_start = Instant::now();

    for chunk in signers.chunks(parallel_verify) {
        let futs = chunk.iter().enumerate().map(|(idx, signer)| {
            let signer = signer.clone();
            let watcher_url = watcher_url.clone();
            let http = http.clone();
            async move {
                let t = Instant::now();
                let r = run_verifier(idx, &signer, &watcher_url, &http).await;
                (t.elapsed(), r)
            }
        });
        for (elapsed, res) in join_all(futs).await {
            match res {
                Ok(()) => latencies_ms.push(elapsed.as_millis()),
                Err(e) => failures.push(e.to_string()),
            }
        }
    }
    let verify_elapsed = verify_start.elapsed();

    // 5. Print stats --------------------------------------------------------
    if latencies_ms.is_empty() {
        println!("\nNO successful verifier flows. Sample failures:");
        for f in failures.iter().take(5) {
            println!("  - {}", f);
        }
    } else {
        latencies_ms.sort_unstable();
        let p = |q: f64| -> u128 {
            let idx = ((latencies_ms.len() as f64 - 1.0) * q).round() as usize;
            latencies_ms[idx]
        };
        let sum: u128 = latencies_ms.iter().sum();
        let avg = sum / latencies_ms.len() as u128;
        println!(
            "\n=== verifier flow latency over {}/{} identifiers (failed={}) ===",
            latencies_ms.len(),
            n_identifiers,
            failures.len()
        );
        println!("total wall time : {:.2}s", verify_elapsed.as_secs_f64());
        println!("avg             : {} ms", avg);
        println!("min             : {} ms", latencies_ms.first().copied().unwrap_or(0));
        println!("p50             : {} ms", p(0.50));
        println!("p90             : {} ms", p(0.90));
        println!("p95             : {} ms", p(0.95));
        println!("p99             : {} ms", p(0.99));
        println!("max             : {} ms", latencies_ms.last().copied().unwrap_or(0));
    }

    // 6. Render Prometheus metrics via our local handle --------------------
    let body = metrics_handle.render();
    println!("\n=== watcher metrics (selected) ===");
    let interesting: Vec<&str> = body
        .lines()
        .filter(|l| {
            !l.starts_with('#')
                && (l.contains("keri_watcher_kel_fetch_seconds")
                    || l.contains("keri_watcher_witness_query_seconds")
                    || l.contains("keri_watcher_oobi_resolve_seconds")
                    || l.contains("keri_watcher_handler_seconds")
                    || l.contains("keri_witness_handler_seconds")
                    || l.contains("keri_witness_query_processing_seconds")
                    || l.contains("keri_watcher_witness_query_failures_total"))
                && (l.contains("_count") || l.contains("_sum"))
        })
        .collect();
    for line in interesting {
        println!("{}", line);
    }
    let dump_path = std::env::var("PERF_METRICS_DUMP")
        .unwrap_or_else(|_| "/tmp/perf_watcher_metrics.txt".to_string());
    std::fs::write(&dump_path, &body)?;
    println!("\nfull metrics dump written to {}", dump_path);

    Ok(())
}

const LATENCY_BUCKETS: &[f64] = &[
    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 20.0, 30.0, 60.0,
];

fn install_prometheus_recorder() -> PrometheusHandle {
    PrometheusBuilder::new()
        .set_buckets_for_metric(Matcher::Suffix("_seconds".to_string()), LATENCY_BUCKETS)
        .expect("valid bucket config")
        .install_recorder()
        .expect("install Prometheus recorder")
}

async fn create_signer(idx: usize, witnesses: &[&WitnessHandle]) -> Result<Signer> {
    let dir: PathBuf = Builder::new()
        .prefix(&format!("perf-signer{}-", idx))
        .tempdir()?
        .keep();
    let km = CryptoBox::new()?;
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: dir,
        ..Default::default()
    })?);

    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());
    let oobis: Vec<LocationScheme> = witnesses.iter().map(|w| w.oobi.clone()).collect();
    let icp = controller.incept(vec![pk], vec![npk], oobis, 1).await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(icp.as_bytes())?);
    let mut signer = controller.finalize_incept(icp.as_bytes(), &sig)?;
    signer.notify_witnesses().await?;

    let wit_ids: Vec<BasicPrefix> = witnesses.iter().map(|w| w.id.clone()).collect();
    for qry in signer.query_mailbox(signer.id(), &wit_ids)? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode()?)?);
        signer
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    Ok(Signer {
        id: signer.id().clone(),
        witnesses: witnesses.iter().map(|w| (*w).clone()).collect(),
    })
}

/// Drive the watcher's KEL-fetch path directly via its HTTP API.
///
///   1. POST /resolve LocationScheme — for each of the signer's witnesses,
///      so the watcher knows where to reach them.
///   2. POST /resolve EndRole{Witness} — watcher then hits the witness's
///      `/oobi/{cid}/{role}/{eid}` and ingests the returned KEL.
///
/// Step 2 is the headline AID-verification-equivalent latency: from the
/// outside it looks like "I asked the watcher about an unknown AID, how
/// long until it had the KEL?".
async fn run_verifier(
    _idx: usize,
    signer: &Signer,
    watcher_url: &Url,
    http: &reqwest::Client,
) -> Result<()> {
    let resolve_url = watcher_url.join("resolve").unwrap();

    for w in &signer.witnesses {
        let body = serde_json::to_string(&w.oobi)?;
        let resp = http
            .post(resolve_url.clone())
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "watcher /resolve LocationScheme failed: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
    }

    let end_role = EndRole {
        cid: signer.id.clone(),
        role: keri_core::oobi::Role::Witness,
        eid: IdentifierPrefix::Basic(signer.witnesses[0].id.clone()),
    };
    let body = serde_json::to_string(&end_role)?;
    let resp = http
        .post(resolve_url.clone())
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!(
            "watcher /resolve EndRole failed: {} {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }
    Ok(())
}
