use std::sync::Arc;

use controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri::actor::prelude::HashFunctionCode;
use said::derivation::HashFunction;

#[async_std::test]
async fn test_tel() -> Result<(), ControllerError> {
    use tempfile::Builder;

    // Incept keri identifier
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller1 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            ..Default::default()
        })
        .unwrap(),
    );

    let km1 = CryptoBox::new().unwrap();
    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller1
            .incept(vec![pk], vec![npk], vec![], 0)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

        let incepted_identifier = controller1
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller1.clone())
    };
    let issuer_prefix = identifier1.id.clone();

    // Incept management TEL
    let tel_root = Builder::new().prefix("tel-test-db").tempdir().unwrap();

    let ixn = identifier1.incept_registry(tel_root.path()).unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&ixn).unwrap());

    identifier1.finalize_event(&ixn, signature).await.unwrap();

    let tel_ref = identifier1.tel.as_ref().unwrap();
    let mana = tel_ref.get_management_tel_state().unwrap();
    assert_eq!(mana.sn, 0);

    // Issue something (sign and create ixn event to kel)
    let credential = r#"{"blabla":"bla"}"#;
    let vc_hash = HashFunction::from(HashFunctionCode::Blake3_256).derive(credential.as_bytes());

    let issuance_ixn = identifier1.issue(credential).unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&issuance_ixn).unwrap());

    identifier1
        .finalize_event(&issuance_ixn, signature)
        .await
        .unwrap();

    let state = identifier1
        .source
        .storage
        .get_state(&issuer_prefix)
        .unwrap()
        .unwrap(); // .get_last_establishment_event_seal(&issuer_prefix).unwrap().unwrap();

    assert_eq!(state.sn, 2);
    let iss = tel_ref.get_vc_state(&vc_hash).unwrap();
    assert!(matches!(iss, teliox::state::vc_state::TelState::Issued(_)));

    // Revoke issued credential
    let revocation_ixn = identifier1.revoke(&vc_hash).unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&revocation_ixn).unwrap());

    identifier1
        .finalize_event(&revocation_ixn, signature)
        .await
        .unwrap();

    let state = identifier1
        .source
        .storage
        .get_state(&issuer_prefix)
        .unwrap()
        .unwrap(); // .get_last_establishment_event_seal(&issuer_prefix).unwrap().unwrap();

    assert_eq!(state.sn, 3);
    let rev = tel_ref.get_vc_state(&vc_hash).unwrap();
    assert!(matches!(rev, teliox::state::vc_state::TelState::Revoked));

    Ok(())
}
