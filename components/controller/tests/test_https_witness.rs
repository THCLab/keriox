//! A witness that advertises only an https location is as usable as one
//! that advertises http.

use std::{collections::HashMap, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, BasicPrefix, CryptoBox, KeyManager,
    LocationScheme, SelfSigningPrefix,
};
use keri_core::{
    oobi::Scheme,
    prefix::IdentifierPrefix,
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::{Host, Url};
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn an_https_only_witness_receipts_the_inception() {
    let root = Builder::new().prefix("https-wit-ctrl").tempdir().unwrap();
    let witness_root = Builder::new().prefix("https-wit").tempdir().unwrap();
    let witness = Arc::new(
        WitnessListener::setup_with_redb(
            Url::parse("https://witness1:3232/").unwrap(),
            witness_root.path(),
            None,
            WitnessEscrowConfig::default(),
            keri_core::event_message::keri_version::KeriVersion::V1_0,
        )
        .unwrap(),
    );
    let witness_id = witness.get_prefix();
    let mut actors: TestActorMap = HashMap::new();
    actors.insert((Host::Domain("witness1".to_string()), 3232), witness);
    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(TestTransport::new(actors)),
        ..Default::default()
    })
    .unwrap();

    let keys = CryptoBox::new().unwrap();
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            vec![LocationScheme {
                eid: IdentifierPrefix::Basic(witness_id.clone()),
                scheme: Scheme::Https,
                url: Some(Url::parse("https://witness1:3232/").unwrap()),
            }],
            1,
        )
        .await
        .unwrap();
    let sig = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes()).unwrap());
    let mut identifier = controller.finalize_incept(icp.as_bytes(), &sig).unwrap();
    identifier.notify_witnesses().await.unwrap();

    let id = identifier.id().clone();
    let queries = identifier
        .query_receipts(&id, &[witness_id])
        .unwrap()
        .into_iter()
        .map(|qry| {
            let sig = keys.sign(&qry.encode().unwrap()).unwrap();
            (qry, SelfSigningPrefix::Ed25519Sha512(sig))
        })
        .collect();
    let errors = identifier.finalize_query_receipts(queries).await.unwrap();
    assert!(errors.is_empty(), "{errors:?}");

    let state = identifier.find_state(identifier.id()).unwrap();
    assert_eq!(
        state.sn, 0,
        "the witness receipt makes the inception accepted"
    );
}
