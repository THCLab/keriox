use std::{path::Path, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::{query::QueryResponse, Identifier}, BasicPrefix,
    CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_core::{actor::error::ActorError, transport::test::TestTransport};
use transport::TelTestTransport;

pub mod transport;

// Helper function that incepts identifier
pub async fn setup_identifier(
    root_path: &Path,
    witness_locations: Vec<LocationScheme>,
    transport: Option<TestTransport<ActorError>>,
    tel_transport: Option<TelTestTransport>,
) -> (Identifier, CryptoBox, Arc<Controller>) {
    let verifier_controller = Arc::new(
        match (transport, tel_transport) {
            (None, None) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                ..Default::default()
            }),
            (None, Some(tel_transport)) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                tel_transport: Box::new(tel_transport.clone()),
                ..Default::default()
            }),
            (Some(transport), None) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                transport: Box::new(transport.clone()),
                ..Default::default()
            }),
            (Some(transport), Some(tel_transport)) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                transport: Box::new(transport.clone()),
                tel_transport: Box::new(tel_transport.clone()),
                ..Default::default()
            }),
        }
        .unwrap(),
    );

    let witnesses_id: Vec<BasicPrefix> = witness_locations
        .iter()
        .map(|loc| match &loc.eid {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => unreachable!(),
        })
        .collect();

    let verifier_keypair = CryptoBox::new().unwrap();

    let pk = BasicPrefix::Ed25519NT(verifier_keypair.public_key());
    let npk = BasicPrefix::Ed25519NT(verifier_keypair.next_public_key());

    let icp_event = verifier_controller
        .incept(vec![pk], vec![npk], witness_locations, 1)
        .await
        .unwrap();
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(icp_event.as_bytes()).unwrap());

    let mut verifier = verifier_controller
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();

    assert_eq!(verifier.notify_witnesses().await.unwrap(), 1);

    // Querying mailbox to get receipts
    for qry in verifier
        .query_mailbox(verifier.id(), &witnesses_id)
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
        );
        let act = verifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
        matches!(act, QueryResponse::Updates);
    }
    (verifier, verifier_keypair, verifier_controller)
}

mod example {
    use keri_controller::{BasicPrefix, LocationScheme};

    pub fn _first_witness_data() -> (BasicPrefix, LocationScheme) {
        let first_witness_id: BasicPrefix = "BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"
            .parse()
            .unwrap();
        // OOBI (Out-Of-Band Introduction) specifies the way how actors can be found.
        let first_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}}"#,
        first_witness_id
    ))
    .unwrap();
        (first_witness_id, first_witness_oobi)
    }

    pub fn _second_witness_data() -> (BasicPrefix, LocationScheme) {
        let second_witness_id: BasicPrefix = "BDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP"
            .parse()
            .unwrap();
        let second_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness3.sandbox.argo.colossi.network/"}}"#,
        second_witness_id
    ))
    .unwrap();
        (second_witness_id, second_witness_oobi)
    }

    pub fn _watcher_data() -> (BasicPrefix, LocationScheme) {
        let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b"
            .parse()
            .unwrap();
        let watcher_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}}"#,
        watcher_id
    ))
    .unwrap();
        (watcher_id, watcher_oobi)
    }
}
