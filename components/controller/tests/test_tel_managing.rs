use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError, BasicPrefix,
    CryptoBox, KeyManager, SelfSigningPrefix,
};
use keri_core::actor::prelude::{HashFunction, HashFunctionCode};

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
    let pk = BasicPrefix::Ed25519(km1.public_key());
    let npk = BasicPrefix::Ed25519(km1.next_public_key());

    let icp_event = controller1
        .incept(vec![pk], vec![npk], vec![], 0)
        .await
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes()).unwrap());

    let mut identifier1 = controller1
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();

    let issuer_prefix = identifier1.id().clone();

    // Incept management TEL
    let (_registry_id, ixn) = identifier1.incept_registry().unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&ixn).unwrap());

    identifier1
        .finalize_incept_registry(&ixn, signature)
        .await
        .unwrap();

    println!("Id registry: {:?}", identifier1.registry_id());

    let mana = identifier1
        .find_management_tel_state(identifier1.registry_id().unwrap())
        .unwrap()
        .unwrap();
    assert_eq!(mana.sn, 0);

    // Issue something (sign and create ixn event to kel)
    let credential = r#"message"#.to_string();
    let credential_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(credential.as_bytes());

    let (vc_id, issuance_ixn) = identifier1.issue(credential_said).unwrap();
    let vc_hash = match vc_id {
        keri_controller::IdentifierPrefix::SelfAddressing(sai) => sai.said.clone(),
        _ => unreachable!(),
    };
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&issuance_ixn).unwrap());

    identifier1
        .finalize_issue(&issuance_ixn, signature)
        .await
        .unwrap();

    let state = identifier1.find_state(&issuer_prefix)?;

    assert_eq!(state.sn, 2);
    let iss = identifier1.find_vc_state(&vc_hash).unwrap();
    assert!(matches!(
        iss,
        Some(teliox::state::vc_state::TelState::Issued(_))
    ));

    // Revoke issued credential
    let revocation_ixn = identifier1.revoke(&vc_hash).unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&revocation_ixn).unwrap());

    identifier1
        .finalize_revoke(&revocation_ixn, signature)
        .await
        .unwrap();

    let state = identifier1.find_state(&issuer_prefix)?;

    assert_eq!(state.sn, 3);
    let rev = identifier1.find_vc_state(&vc_hash).unwrap();
    assert!(matches!(
        rev,
        Some(teliox::state::vc_state::TelState::Revoked)
    ));

    Ok(())
}
