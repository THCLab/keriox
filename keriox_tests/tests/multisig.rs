use std::{collections::HashMap, net::Ipv4Addr, sync::Arc};

use anyhow::Result;
use controller::{identifier_controller::IdentifierController, utils::OptionalConfig, Controller};
use keri::{
    event_parsing::codes::self_signing::SelfSigning,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::{Host, Url};
use watcher::WatcherListener;
use witness::WitnessListener;

#[async_std::test]
async fn test_multisig() -> Result<()> {
    let wit = {
        let wit_root = Builder::new().prefix("wit-db").tempdir().unwrap();
        WitnessListener::setup(
            Url::parse("http://127.0.0.1:3232").unwrap(),
            None,
            wit_root.path(),
            Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".to_string()),
        )?
    };

    let watcher_url = Url::parse("http://127.0.0.1:3236").unwrap();
    let watcher_listener = {
        let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
        WatcherListener::setup(watcher_url.clone(), None, root.path(), None)?
    };
    let watcher = watcher_listener.watcher_data.clone();
    let watcher_id = watcher.0.prefix.clone();
    // let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b".parse().unwrap();

    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Ipv4(Ipv4Addr::LOCALHOST), 3232), Arc::new(wit));
    actors.insert(
        (Host::Ipv4(Ipv4Addr::LOCALHOST), 3236),
        Arc::new(watcher_listener),
    );
    let transport = TestTransport::new(actors);

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());
    let controller =
        Arc::new(Controller::with_transport(Some(initial_config), Box::new(transport)).unwrap());
    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    let identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller.clone())
    };

    // Watcher should know both controllers
    // watcher.parse_and_process_notices(&asker_icp).unwrap();
    // watcher.parse_and_process_notices(&about_icp).unwrap();

    let watcher_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url: watcher_url,
    };
    identifier1
        .source
        .resolve_loc_schema(&watcher_oobi)
        .await
        .unwrap();

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(add_watcher.as_bytes()).unwrap(),
    );
    identifier1
        .finalize_event(add_watcher.as_bytes(), query_sig)
        .await
        .unwrap();

    let query = identifier1
        .query_watcher(&identifier2.id, IdentifierPrefix::Basic(watcher_id))
        .unwrap();
    let query_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(&query.serialize()?).unwrap(),
    );
    identifier1
        .finalize_query(vec![(query, query_sig)])
        .await
        .unwrap();

    Ok(())
}
