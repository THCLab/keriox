//! Compares signing+verification of an identifier backed by N witnesses
//! (with witness threshold = N) for N = 1, 2, 3.
//!
//! Was added because of a report that an identifier with two witnesses
//! could not have its signed messages verified end-to-end.
//!
//! Each scenario runs a full roundtrip: signer incepts with N witnesses
//! and threshold N, signs a payload, then a separate verifier resolves
//! the signer's KEL via a watcher and verifies the signature. The local
//! `controller.verify` call and the full KEL-fetch + verify cycle are
//! timed and printed.

use std::{net::Ipv4Addr, sync::Arc, time::{Duration, Instant}};

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    identifier::query::QueryResponse, BasicPrefix, CryptoBox, EndRole, IdentifierPrefix,
    KeyManager, LocationScheme, Oobi, SelfSigningPrefix,
};
use tempfile::Builder;
use url::Url;
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

struct WitnessHandle {
    id: BasicPrefix,
    oobi: LocationScheme,
}

async fn spawn_witness(port: u16, seed: &str) -> WitnessHandle {
    let url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
    let wit = Arc::new(
        WitnessListener::setup_with_redb(
            url.clone(),
            wit_root.path(),
            Some(seed.to_string()),
            WitnessEscrowConfig::default(),
        )
        .unwrap(),
    );
    let id = wit.get_prefix();
    let oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: url.clone(),
    };
    actix_rt::spawn(wit.listen_http((Ipv4Addr::UNSPECIFIED, port)));
    // Leak the tempdir so it lives for the duration of the test process.
    std::mem::forget(wit_root);
    WitnessHandle { id, oobi }
}

async fn spawn_watcher(port: u16) -> (BasicPrefix, LocationScheme) {
    let url = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
    let tel_dir = Builder::new().prefix("watcher-tel-db").tempdir().unwrap();
    let tel_path = tel_dir.path().join("tel_storage");
    let root = Builder::new().prefix("watcher-db").tempdir().unwrap();
    let listener = WatcherListener::setup_with_redb(WatcherConfig {
        public_address: url.clone(),
        db_path: root.path().to_owned(),
        tel_storage_path: tel_path,
        ..Default::default()
    })
    .unwrap();
    let id = listener.watcher.prefix();
    let oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: url.clone(),
    };
    actix_rt::spawn(listener.listen_http((Ipv4Addr::UNSPECIFIED, port)));
    std::mem::forget(tel_dir);
    std::mem::forget(root);
    (id, oobi)
}

struct ScenarioTiming {
    n_witnesses: usize,
    kel_fetch_and_verify: std::time::Duration,
    local_verify_only: std::time::Duration,
}

async fn run_scenario(
    label: &str,
    witnesses: &[&WitnessHandle],
    watcher_id: &BasicPrefix,
    watcher_oobi: &LocationScheme,
) -> Result<ScenarioTiming, ControllerError> {
    let n = witnesses.len();
    let threshold = n as u64;
    let witness_oobis: Vec<LocationScheme> = witnesses.iter().map(|w| w.oobi.clone()).collect();
    let witness_ids: Vec<BasicPrefix> = witnesses.iter().map(|w| w.id.clone()).collect();
    eprintln!("[{label}] start scenario, threshold={threshold}");

    // ---- Signer ----
    let signer_db = Builder::new().prefix("signer-db").tempdir().unwrap();
    let signer_km = CryptoBox::new()?;
    let signer_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: signer_db.path().to_owned(),
        ..Default::default()
    })?);

    let pk = BasicPrefix::Ed25519(signer_km.public_key());
    let npk = BasicPrefix::Ed25519(signer_km.next_public_key());

    let icp_event = signer_controller
        .incept(vec![pk], vec![npk], witness_oobis.clone(), threshold)
        .await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(signer_km.sign(icp_event.as_bytes())?);
    let mut signer = signer_controller.finalize_incept(icp_event.as_bytes(), &sig)?;

    signer.notify_witnesses().await.unwrap();

    // Pull receipts from every witness so the inception is fully accepted.
    for qry in signer.query_mailbox(signer.id(), &witness_ids)? {
        let qsig = SelfSigningPrefix::Ed25519Sha512(signer_km.sign(&qry.encode()?)?);
        signer.finalize_query_mailbox(vec![(qry, qsig)]).await?;
    }

    let event_seal = signer
        .get_last_establishment_event_seal()
        .expect("inception with full witness threshold should be accepted");
    eprintln!("[{label}] signer incepted: {}", signer.id());

    // Sign a payload.
    let payload = format!("hello from {label}").into_bytes();
    let payload_sig =
        vec![SelfSigningPrefix::Ed25519Sha512(signer_km.sign(&payload)?)];
    let signature = signer.sign_data(&payload, &payload_sig)?;

    // ---- Verifier ----
    // Verifier only needs one of the signer's witnesses to incept itself,
    // so the verifier setup cost is constant across scenarios.
    let verifier_db = Builder::new().prefix("verifier-db").tempdir().unwrap();
    let verifier_km = CryptoBox::new()?;
    let verifier_controller = Arc::new(Controller::new(ControllerConfig {
        db_path: verifier_db.path().to_owned(),
        ..Default::default()
    })?);

    let vpk = BasicPrefix::Ed25519(verifier_km.public_key());
    let vnpk = BasicPrefix::Ed25519(verifier_km.next_public_key());
    let v_icp = verifier_controller
        .incept(vec![vpk], vec![vnpk], vec![witnesses[0].oobi.clone()], 1)
        .await?;
    let v_sig = SelfSigningPrefix::Ed25519Sha512(verifier_km.sign(v_icp.as_bytes())?);
    let mut verifier = verifier_controller.finalize_incept(v_icp.as_bytes(), &v_sig)?;
    verifier.notify_witnesses().await.unwrap();
    for qry in verifier.query_mailbox(verifier.id(), &[witnesses[0].id.clone()])? {
        let qsig = SelfSigningPrefix::Ed25519Sha512(verifier_km.sign(&qry.encode()?)?);
        verifier.finalize_query_mailbox(vec![(qry, qsig)]).await?;
    }

    // Hook the verifier to the watcher.
    verifier
        .resolve_oobi(&Oobi::Location(watcher_oobi.clone()))
        .await?;
    let add_watcher = verifier.add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))?;
    let aw_sig =
        SelfSigningPrefix::Ed25519Sha512(verifier_km.sign(add_watcher.as_bytes())?);
    verifier
        .finalize_add_watcher(add_watcher.as_bytes(), aw_sig)
        .await?;

    // Tell the watcher about every signer witness so it can fetch the KEL.
    for w in witnesses {
        let oobi = Oobi::Location(w.oobi.clone());
        verifier.resolve_oobi(&oobi).await?;
        verifier
            .send_oobi_to_watcher(&verifier.id(), &oobi)
            .await?;
    }
    // Bind the signer to (at least) one of the witnesses for the watcher.
    let signer_endrole = EndRole {
        cid: signer.id().clone(),
        role: keri_core::oobi::Role::Witness,
        eid: IdentifierPrefix::Basic(witnesses[0].id.clone()),
    };
    verifier
        .send_oobi_to_watcher(&verifier.id(), &Oobi::EndRole(signer_endrole))
        .await?;
    eprintln!("[{label}] verifier ready, watcher hooked up");

    // ---- Timed: query KEL and verify ----
    let t0 = Instant::now();
    let queries: Vec<_> = verifier
        .query_watchers(&event_seal)?
        .into_iter()
        .map(|qry| {
            let s = SelfSigningPrefix::Ed25519Sha512(
                verifier_km.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, s)
        })
        .collect();

    // Cap the watcher poll loop so a stalled watcher fails loudly instead
    // of hanging the whole test.
    let poll_deadline = Instant::now() + Duration::from_secs(30);
    let mut polls = 0u32;
    let (mut response, _) = verifier.finalize_query(queries.clone()).await;
    while let QueryResponse::NoUpdates = response {
        polls += 1;
        if Instant::now() >= poll_deadline {
            panic!(
                "[{label}] watcher returned NoUpdates for >30s after {polls} polls — \
                 KEL never propagated to verifier"
            );
        }
        actix_rt::time::sleep(Duration::from_millis(100)).await;
        (response, _) = verifier.finalize_query(queries.clone()).await;
    }
    eprintln!("[{label}] watcher returned KEL after {polls} polls");

    // Local verify only (KEL already in place).
    let t_verify_start = Instant::now();
    verifier_controller
        .verify(&payload, &signature)
        .expect("verification must succeed");
    let local_verify_only = t_verify_start.elapsed();
    let kel_fetch_and_verify = t0.elapsed();

    // Sanity-check: a second verify is always a local op.
    verifier_controller.verify(&payload, &signature).unwrap();

    Ok(ScenarioTiming {
        n_witnesses: n,
        kel_fetch_and_verify,
        local_verify_only,
    })
}

#[actix_rt::test]
async fn witness_count_signing_perf() -> Result<(), ControllerError> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "off".parse().unwrap()),
        )
        .with_test_writer()
        .try_init();
    // Distinct ports from `InfrastructureContext` so this test can coexist.
    let w1 = spawn_witness(3340, "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH").await;
    let w2 = spawn_witness(3341, "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP").await;
    let w3 = spawn_witness(3342, "ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc").await;
    let (watcher_id, watcher_oobi) = spawn_watcher(3346).await;

    let scenarios: Vec<(&str, Vec<&WitnessHandle>)> = vec![
        ("1-witness", vec![&w1]),
        ("2-witness", vec![&w1, &w2]),
        ("3-witness", vec![&w1, &w2, &w3]),
    ];

    let mut timings = Vec::new();
    for (label, wits) in scenarios {
        let t = run_scenario(label, &wits, &watcher_id, &watcher_oobi).await?;
        println!(
            "[{label}] kel_fetch+verify = {:?}, local verify = {:?}",
            t.kel_fetch_and_verify, t.local_verify_only
        );
        timings.push(t);
    }

    println!("\n=== witness count vs verification time ===");
    println!(
        "{:>10} | {:>22} | {:>18}",
        "witnesses", "kel_fetch+verify", "local_verify"
    );
    for t in &timings {
        println!(
            "{:>10} | {:>22?} | {:>18?}",
            t.n_witnesses, t.kel_fetch_and_verify, t.local_verify_only
        );
    }

    Ok(())
}
