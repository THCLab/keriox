use std::{net::Ipv4Addr, sync::Arc};

use keri_controller::{BasicPrefix, IdentifierPrefix, LocationScheme};
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

impl AsyncTestContext for InfrastructureContext {
    async fn setup() -> InfrastructureContext {
        let first_witness = {
            let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup(
                    Url::parse("http://127.0.0.1:3232").unwrap(),
                    wit_root.path(),
                    Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".to_string()),
                    WitnessEscrowConfig::default(),
                )
                .unwrap(),
            )
        };
        let first_witness_id = first_witness.get_prefix();
        let first_witness_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(first_witness_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: Url::parse("http://127.0.0.1:3232").unwrap(),
        };

        async_std::task::spawn(first_witness.listen_http((Ipv4Addr::UNSPECIFIED, 3232)));


        let second_witness = {
            let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup(
                    Url::parse("http://127.0.0.1:3233").unwrap(),
                    wit_root.path(),
                    Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAd".to_string()),
                    WitnessEscrowConfig::default(),
                )
                .unwrap(),
            )
        };
        let second_witness_id = second_witness.get_prefix();
        let second_witness_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(second_witness_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: Url::parse("http://127.0.0.1:3233").unwrap(),
        };

        async_std::task::spawn(second_witness.listen_http((Ipv4Addr::UNSPECIFIED, 3233)));

        let watcher_url = Url::parse("http://127.0.0.1:3236").unwrap();
        let watcher_tel_dir = Builder::new().prefix("cont-test-tel-db").tempdir().unwrap();
        let watcher_tel_path = watcher_tel_dir.path().join("tel_storage");

        let watcher_listener = {
            let root = Builder::new().prefix("watcher-test-db").tempdir().unwrap();
            WatcherListener::new(WatcherConfig {
                public_address: watcher_url.clone(),
                db_path: root.path().to_owned(),
                tel_storage_path: watcher_tel_path,
                ..Default::default()
            })
            .unwrap()
        };
        let watcher = watcher_listener.watcher.clone();
        let watcher_id = watcher.prefix();
        let watcher_oobi = LocationScheme {
            eid: IdentifierPrefix::Basic(watcher_id.clone()),
            scheme: keri_core::oobi::Scheme::Http,
            url: watcher_url.clone(),
        };
        async_std::task::spawn(watcher_listener.listen_http((Ipv4Addr::UNSPECIFIED, 3236)));

        InfrastructureContext {
            first_witness_oobi,
            second_witness_oobi,
            watcher_oobi,
        }
    }

    async fn teardown(self) {
    }
}

impl  InfrastructureContext {
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