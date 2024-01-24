use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier_controller::IdentifierController,
    BasicPrefix, Controller, CryptoBox, KeyManager, SelfSigningPrefix,
};
use tempfile::Builder;

#[async_std::test]
async fn test_kel_managing() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);
    let mut km = CryptoBox::new()?;

    // Incept identifier
    let identifier1 = {
        let pk = BasicPrefix::Ed25519(km.public_key());
        let npk = BasicPrefix::Ed25519(km.next_public_key());

        let icp_event = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(icp_event.as_bytes())?);

        let incept_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incept_identifier, controller.clone(), None)
    };

    let id_state = controller.get_state(&identifier1.id)?;
    assert_eq!(id_state.sn, 0);

    // Keys rotation
    km.rotate()?;
    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());
    let rotation_event = identifier1
        .rotate(vec![pk], vec![npk], vec![], vec![], 0)
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rotation_event.as_bytes())?);
    identifier1
        .finalize_event(rotation_event.as_bytes(), signature)
        .await?;

    let id_state = controller.get_state(&identifier1.id)?;
    assert_eq!(id_state.sn, 1);

    Ok(())
}
