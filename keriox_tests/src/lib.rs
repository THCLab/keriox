use std::{path::Path, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::Identifier, BasicPrefix,
    CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_core::{actor::error::ActorError, transport::test::TestTransport};
use transport::TelTestTransport;

pub mod settings;
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
        let _act = verifier
            .finalize_mechanics_query(vec![(qry, signature)])
            .await
            .unwrap();
    }
    (verifier, verifier_keypair, verifier_controller)
}
