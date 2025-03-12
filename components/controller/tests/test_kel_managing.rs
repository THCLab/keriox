use cesrox::primitives::codes::self_addressing::SelfAddressing;
use keri_core::{
    actor::prelude::HashFunction,
    oobi::LocationScheme,
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError};

#[async_std::test]
async fn test_kel_managing() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;

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

#[async_std::test]
async fn test_kel_managing_with_witness() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let first_witness_id: BasicPrefix = "BNJJhjUnhlw-lsbYdehzLsX1hJMG9QJlK_wJ5AunJLrM"
        .parse()
        .unwrap();
    // OOBI (Out-Of-Band Introduction) specifies the way how actors can be found.
    let first_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://w1.ea.argo.colossi.network/"}}"#,
        first_witness_id
    ))
    .unwrap();

    let second_witness_id: BasicPrefix = "BFdfJEbC7__AqZdrXkxmW3THnZmIeJzCGpzJpgN6Ettw"
        .parse()
        .unwrap();
    let second_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://w2.ea.argo.colossi.network/"}}"#,
        second_witness_id
    ))
    .unwrap();

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;

    let mut km = CryptoBox::new()?;

    let first_pk = BasicPrefix::Ed25519(km.public_key());
    let first_next_npk = BasicPrefix::Ed25519(km.next_public_key());
    let inception_event = controller
        .incept(
            vec![first_pk.clone()],
            vec![first_next_npk],
            vec![first_witness_oobi, second_witness_oobi],
            1,
        )
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(inception_event.as_bytes())?);

    let mut identifier = controller.finalize_incept(inception_event.as_bytes(), &signature)?;

    let i = identifier.notify_witnesses().await?;
    dbg!(i);

    let queries_to_sign = identifier.query_mailbox(
        identifier.id(),
        &[first_witness_id.clone(), second_witness_id.clone()],
    )?;

    // Querying witnesses to get receipts
    for qry in queries_to_sign {
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
        identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    let keys = identifier.current_public_keys()?;
    assert_eq!(keys, vec![first_pk.clone()]);

    // Rotate signer keys
    km.rotate()?;
    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());

    // Rotation needs two witness receipts to be accepted
    let rotation_event = identifier
        .rotate(vec![pk.clone()], vec![npk], 1, vec![], vec![], 2)
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(rotation_event.as_bytes())?);
    identifier
        .finalize_rotate(rotation_event.as_bytes(), signature)
        .await?;

    // Publish event to actor's witnesses
    identifier.notify_witnesses().await.unwrap();

    // Querying witnesses to get receipts
    for qry in identifier
        .query_mailbox(
            &identifier.id(),
            &[first_witness_id.clone(), second_witness_id.clone()],
        )
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(&qry.encode().unwrap()).unwrap());
        identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    let keys = identifier.current_public_keys()?;
    assert_eq!(keys, vec![pk.clone()]);

    Ok(())
}
