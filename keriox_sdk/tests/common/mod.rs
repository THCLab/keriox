//! Shared test infrastructure for the end-to-end suite.
//!
//! Spawns *real* witness and watcher services as in-process HTTP servers —
//! the same binaries that run in production deployments — on ephemeral
//! ports, so the tests exercise exactly what a 3rd-party application does:
//! pass a plain base URL to the facade and let it do the rest.

// Each test binary compiles its own copy of this module and uses a subset
// of the helpers, so unused-item warnings here are noise.
#![allow(dead_code)]

use std::net::{Ipv4Addr, TcpListener};
use std::sync::Arc;

use tempfile::TempDir;
use test_context::AsyncTestContext;
use url::Url;
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

/// A running witness with the URL to hand to the facade.
pub struct WitnessHandle {
    pub url: String,
    // Databases live in here; dropped (deleted) with the handle.
    _db_dir: TempDir,
}

/// A running watcher with the URL to hand to the facade.
pub struct WatcherHandle {
    pub url: String,
    _db_dir: TempDir,
}

/// Reserve an ephemeral TCP port.
///
/// Binds to port 0, reads the assigned port, and releases it. There is a
/// tiny window in which another process could grab the port, but tests bind
/// immediately afterwards and each test binary draws from the kernel's
/// ephemeral range, so collisions are practically nonexistent.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("cannot bind to an ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

/// Start a witness on an ephemeral port and return its base URL.
pub fn spawn_witness() -> WitnessHandle {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let db_dir = tempfile::Builder::new()
        .prefix("e2e-witness-db")
        .tempdir()
        .unwrap();

    let listener = Arc::new(
        WitnessListener::setup_with_redb(
            Url::parse(&url).unwrap(),
            db_dir.path(),
            None, // random signing key
            WitnessEscrowConfig::default(),
        )
        .expect("failed to set up witness"),
    );
    actix_rt::spawn(listener.listen_http((Ipv4Addr::LOCALHOST, port)));

    WitnessHandle {
        url,
        _db_dir: db_dir,
    }
}

/// Start a watcher on an ephemeral port and return its base URL.
pub fn spawn_watcher() -> WatcherHandle {
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}");
    let db_dir = tempfile::Builder::new()
        .prefix("e2e-watcher-db")
        .tempdir()
        .unwrap();

    let listener = WatcherListener::setup_with_redb(WatcherConfig {
        public_address: Url::parse(&url).unwrap(),
        db_path: db_dir.path().to_owned(),
        tel_storage_path: db_dir.path().join("tel_storage"),
        ..Default::default()
    })
    .expect("failed to set up watcher");
    actix_rt::spawn(listener.listen_http((Ipv4Addr::LOCALHOST, port)));

    WatcherHandle {
        url,
        _db_dir: db_dir,
    }
}

/// One witness and one watcher — enough infrastructure for most flows.
pub struct TestInfra {
    pub witness: WitnessHandle,
    pub watcher: WatcherHandle,
}

impl AsyncTestContext for TestInfra {
    async fn setup() -> TestInfra {
        TestInfra {
            witness: spawn_witness(),
            watcher: spawn_watcher(),
        }
    }

    async fn teardown(self) {}
}

/// Open a fresh facade store in its own temp directory.
pub fn temp_keri() -> (TempDir, keri_sdk::Keri) {
    let dir = tempfile::Builder::new()
        .prefix("e2e-keri-store")
        .tempdir()
        .unwrap();
    let keri = keri_sdk::Keri::open(dir.path()).unwrap();
    (dir, keri)
}
