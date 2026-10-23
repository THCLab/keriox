use std::{
    net::{Ipv4Addr, TcpListener},
    sync::Arc,
};

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme};
use keri_core::event_message::keri_version::KeriVersion;
use tempfile::Builder;
use test_context::AsyncTestContext;
use url::Url;
use watcher::{WatcherConfig, WatcherListener};
use witness::{WitnessEscrowConfig, WitnessListener};

pub struct InfrastructureContext {
    first_witness_oobi: LocationScheme,
    second_witness_oobi: LocationScheme,
    watcher_oobi: LocationScheme,
}

/// A port nothing listens on right now, so the infrastructure can run next
/// to anything else on the machine, including another test binary.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("cannot bind to an ephemeral port")
        .local_addr()
        .unwrap()
        .port()
}

impl AsyncTestContext for InfrastructureContext {
    async fn setup() -> InfrastructureContext {
        match std::env::var("KERIOX_TEST_NODES") {
            Ok(nodes) => InfrastructureContext::external(&nodes),
            Err(_) => InfrastructureContext::with_version(KeriVersion::V1).await,
        }
    }

    async fn teardown(self) {}
}

/// The same infrastructure with its witnesses and watcher writing KERI 2.0.
pub struct Keri2InfrastructureContext(pub InfrastructureContext);

impl AsyncTestContext for Keri2InfrastructureContext {
    async fn setup() -> Keri2InfrastructureContext {
        Keri2InfrastructureContext(InfrastructureContext::with_version(KeriVersion::V2).await)
    }

    async fn teardown(self) {}
}

impl InfrastructureContext {
    /// Nodes started outside the tests, e.g. of another keriox release by
    /// `compat/check.sh`: `nodes` names the first witness, the second
    /// witness and the watcher as `<seed>@<url>`, separated by spaces.
    pub fn external(nodes: &str) -> InfrastructureContext {
        let location = |node: &str| {
            let (seed, url) = node
                .split_once('@')
                .expect("KERIOX_TEST_NODES entries are <seed>@<url>");
            let signer = keri_core::signer::Signer::new_with_seed(&seed.parse().unwrap()).unwrap();
            LocationScheme {
                eid: IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(signer.public_key())),
                scheme: keri_core::oobi::Scheme::Http,
                url: Some(Url::parse(url).unwrap()),
            }
        };
        let nodes: Vec<_> = nodes.split_whitespace().map(location).collect();
        let [first_witness_oobi, second_witness_oobi, watcher_oobi] = nodes
            .try_into()
            .expect("KERIOX_TEST_NODES names two witnesses and a watcher");
        InfrastructureContext {
            first_witness_oobi,
            second_witness_oobi,
            watcher_oobi,
        }
    }

    /// Two witnesses and a watcher on free ports, writing their own messages
    /// in `version`.
    pub async fn with_version(version: KeriVersion) -> InfrastructureContext {
        let (first_port, second_port, watcher_port) = (free_port(), free_port(), free_port());
        let first_witness = {
            let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup_with_redb(
                    Url::parse(&format!("http://127.0.0.1:{first_port}")).unwrap(),
                    wit_root.path(),
                    Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".to_string()),
                    WitnessEscrowConfig::default(),
                    version,
                )
                .unwrap(),
            )
        };
        let first_witness_id = first_witness.get_prefix();
        let first_witness_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(first_witness_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: Some(Url::parse(&format!("http://127.0.0.1:{first_port}")).unwrap()),
        };

        actix_rt::spawn(first_witness.listen_http((Ipv4Addr::LOCALHOST, first_port)));

        let second_witness = {
            let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup_with_redb(
                    Url::parse(&format!("http://127.0.0.1:{second_port}")).unwrap(),
                    wit_root.path(),
                    Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAd".to_string()),
                    WitnessEscrowConfig::default(),
                    version,
                )
                .unwrap(),
            )
        };
        let second_witness_id = second_witness.get_prefix();
        let second_witness_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(second_witness_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: Some(Url::parse(&format!("http://127.0.0.1:{second_port}")).unwrap()),
        };

        actix_rt::spawn(second_witness.listen_http((Ipv4Addr::LOCALHOST, second_port)));

        let watcher_url = Url::parse(&format!("http://127.0.0.1:{watcher_port}")).unwrap();
        let watcher_tel_dir = Builder::new().prefix("cont-test-tel-db").tempdir().unwrap();
        let watcher_tel_path = watcher_tel_dir.path().join("tel_storage");

        let watcher_listener = {
            let root = Builder::new().prefix("watcher-test-db").tempdir().unwrap();
            WatcherListener::setup_with_redb(WatcherConfig {
                public_address: watcher_url.clone(),
                db_path: root.path().to_owned(),
                tel_storage_path: watcher_tel_path,
                keri_version: version,
                ..Default::default()
            })
            .unwrap()
        };
        let watcher = watcher_listener.watcher.clone();
        let watcher_id = watcher.prefix();
        let watcher_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(watcher_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: Some(watcher_url.clone()),
        };
        actix_rt::spawn(watcher_listener.listen_http((Ipv4Addr::LOCALHOST, watcher_port)));

        InfrastructureContext {
            first_witness_oobi,
            second_witness_oobi,
            watcher_oobi,
        }
    }

    pub fn first_witness_data(&self) -> (BasicPrefix, LocationScheme) {
        if let IdentifierPrefix::Basic(bp) = &self.first_witness_oobi.eid {
            (bp.clone(), self.first_witness_oobi.clone())
        } else {
            unreachable!()
        }
    }

    pub fn second_witness_data(&self) -> (BasicPrefix, LocationScheme) {
        if let IdentifierPrefix::Basic(bp) = &self.second_witness_oobi.eid {
            (bp.clone(), self.second_witness_oobi.clone())
        } else {
            unreachable!()
        }
    }

    pub fn watcher_data(&self) -> (BasicPrefix, LocationScheme) {
        if let IdentifierPrefix::Basic(bp) = &self.watcher_oobi.eid {
            (bp.clone(), self.watcher_oobi.clone())
        } else {
            unreachable!()
        }
    }
}
