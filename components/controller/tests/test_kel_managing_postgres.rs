mod common;

use cesrox::primitives::codes::self_addressing::SelfAddressing;
use keri_core::{
    actor::prelude::HashFunction,
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};

use keri_controller::{
    config::ControllerConfig, controller::PostgresController, error::ControllerError,
};
use tempfile::Builder;

#[async_std::test]
async fn test_kel_managing_postgres() -> Result<(), ControllerError> {
    common::ensure_clean_db();

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = PostgresController::new_postgres(
        &common::get_database_url(),
        ControllerConfig {
            db_path: root.path().to_owned(),
            ..Default::default()
        },
    )
    .await?;

    let mut km = CryptoBox::new()?;

    let first_pk = BasicPrefix::Ed25519(km.public_key());
    let first_next_npk = BasicPrefix::Ed25519(km.next_public_key());
    let inception_event = controller
        .incept(vec![first_pk.clone()], vec![first_next_npk], vec![], 0)
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);
    let mut identifier = controller.finalize_incept(inception_event.as_bytes(), &signature)?;

    let keys = identifier.current_public_keys()?;
    assert_eq!(keys, vec![first_pk.clone()]);

    // Keys rotation
    km.rotate()?;
    let second_pk = BasicPrefix::Ed25519(km.public_key());
    let second_next_pk = BasicPrefix::Ed25519(km.next_public_key());
    let rotation_event = identifier
        .rotate(
            vec![second_pk.clone()],
            vec![second_next_pk],
            1,
            vec![],
            vec![],
            0,
        )
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rotation_event.as_bytes())?);
    identifier
        .finalize_rotate(rotation_event.as_bytes(), signature)
        .await?;

    let keys = identifier.current_public_keys()?;
    assert_ne!(keys, vec![first_pk]);
    assert_eq!(keys, vec![second_pk.clone()]);

    let data_to_anchor = b"Hello world";
    let said = HashFunction::from(SelfAddressing::Blake3_256).derive(data_to_anchor);
    let interaction_event = identifier.anchor(&[said])?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(interaction_event.as_bytes())?);
    identifier
        .finalize_anchor(interaction_event.as_bytes(), signature)
        .await?;

    let keys = identifier.current_public_keys()?;
    assert_eq!(keys, vec![second_pk]);

    let state = identifier.find_state(identifier.id());
    assert_eq!(state.unwrap().sn, 2);

    Ok(())
}
