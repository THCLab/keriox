use keri_controller::{error::ControllerError, BasicPrefix, KeyManager, SelfSigningPrefix};
use keri_tests::{settings::InfrastructureContext, setup_identifier};
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn test_witness_rotation(ctx: &mut InfrastructureContext) -> Result<(), ControllerError> {
    let root0 = Builder::new().prefix("test-db0").tempdir().unwrap();

    let (first_witness_id, first_witness_oobi) = ctx.first_witness_data();
    let (_second_witness_id, second_witness_oobi) = ctx.second_witness_data();

    // Setup identifier with `witness1` as witness
    let (mut identifier, mut controller_keypair, _) =
        setup_identifier(root0.path(), vec![first_witness_oobi.clone()], None, None).await;

    let state = identifier.find_state(identifier.id())?;
    assert_eq!(state.sn, 0);

    // Rotate witness to `witness2`
    controller_keypair.rotate()?;
    let new_curr = BasicPrefix::Ed25519NT(controller_keypair.public_key());
    let new_next = BasicPrefix::Ed25519NT(controller_keypair.next_public_key());
    let rotation_event = identifier
        .rotate(
            vec![new_curr],
            vec![new_next],
            1,
            vec![second_witness_oobi],
            vec![first_witness_id],
            1,
        )
        .await?;

    let signature =
        SelfSigningPrefix::Ed25519Sha512(controller_keypair.sign(rotation_event.as_bytes())?);
    identifier
        .finalize_rotate(rotation_event.as_bytes(), signature)
        .await?;

    let cached_witnesses = &identifier.witnesses().collect::<Vec<_>>();
    // dbg!(&cached_witnesses);
    let state = identifier.find_state(identifier.id())?;
    // Missing witness receipts, so rotation is not accepted yet.
    assert_eq!(state.sn, 0);
    assert_ne!(&state.witness_config.witnesses, cached_witnesses);

    identifier.notify_witnesses().await.unwrap();
    // Querying mailbox to get receipts
    for qry in identifier
        .query_mailbox(identifier.id(), &cached_witnesses)
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            controller_keypair.sign(&qry.encode().unwrap()).unwrap(),
        );
        let _act = identifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }

    let state = identifier.find_state(identifier.id())?;
    assert_eq!(state.sn, 1);
    assert_eq!(&state.witness_config.witnesses, cached_witnesses);

    Ok(())
}
