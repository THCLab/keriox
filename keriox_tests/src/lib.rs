use std::{path::Path, sync::Arc};

use keri_controller::{
    config::ControllerConfig, identifier_controller::IdentifierController, BasicPrefix, Controller,
    CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_core::{actor::error::ActorError, transport::test::TestTransport};
use transport::TelTestTransport;

pub mod transport;

// Helper function that incepts identifier
pub async fn setup_identifier(
    root_path: &Path,
    witness_locations: Vec<LocationScheme>,
    transport: TestTransport<ActorError>,
    tel_transport: TelTestTransport,
) -> (IdentifierController, CryptoBox) {
    let verifier_controller = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root_path.to_owned(),
            transport: Box::new(transport.clone()),
            tel_transport: Box::new(tel_transport.clone()),
            ..Default::default()
        })
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

    let verifier = {
        let pk = BasicPrefix::Ed25519(verifier_keypair.public_key());
        let npk = BasicPrefix::Ed25519(verifier_keypair.next_public_key());

        let icp_event = verifier_controller
            .incept(vec![pk], vec![npk], witness_locations, 1)
            .await
            .unwrap();
        let signature =
            SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = verifier_controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, verifier_controller.clone(), None)
    };

    assert_eq!(verifier.notify_witnesses().await.unwrap(), 1);

    // Querying mailbox to get receipts
    for qry in verifier.query_mailbox(&verifier.id, &witnesses_id).unwrap() {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
        );
        let act = verifier
            .finalize_query(vec![(qry, signature)])
            .await
            .unwrap();
        assert_eq!(act.len(), 0);
    }
    (verifier, verifier_keypair)
}
