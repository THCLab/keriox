use std::{collections::HashMap, sync::Arc};

use keri_controller::{
    error::ControllerError, BasicPrefix, IdentifierPrefix, KeyManager, LocationScheme,
    SelfSigningPrefix,
};
use keri_core::transport::test::TestTransport;
use keri_tests::{setup_identifier, transport::TelTestTransport};
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

#[async_std::test]
async fn test_witness_rotation() -> Result<(), ControllerError> {
    use url::Url;
    let root0 = Builder::new().prefix("test-db0").tempdir().unwrap();

    // Setup first witness
    let witness1 = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness1/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let wit1_id = witness1.get_prefix();
    let wit1_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit1_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://witness1/").unwrap(),
    };

    // Setup second witness
    let witness2 = {
        // let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit2-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness2/").unwrap(),
                witness_root.path(),
                None,
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let wit2_id = witness2.get_prefix();
    let wit2_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit2_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://witness2/").unwrap(),
    };

    let transport = {
        let mut actors: keri_core::transport::test::TestActorMap = HashMap::new();
        actors.insert((Host::Domain("witness1".to_string()), 80), witness1.clone());
        actors.insert((Host::Domain("witness2".to_string()), 80), witness2.clone());
        TestTransport::new(actors)
    };

    // Setup identifier with `witness1` as witness
    let (mut identifier, mut controller_keypair, _) = setup_identifier(
        root0.path(),
        vec![wit1_location.clone()],
        Some(transport.clone()),
        Some(TelTestTransport::new()),
    )
    .await;

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
            vec![wit2_location],
            vec![wit1_id],
            1,
        )
        .await?;

    let signature =
        SelfSigningPrefix::Ed25519Sha512(controller_keypair.sign(rotation_event.as_bytes())?);
    identifier
        .finalize_event(rotation_event.as_bytes(), signature)
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
        let act = identifier
            .finalize_mechanics_query(vec![(qry, signature)])
            .await
            .unwrap();
    }

    let state = identifier.find_state(identifier.id())?;
    assert_eq!(state.sn, 1);
    assert_eq!(&state.witness_config.witnesses, cached_witnesses);

    Ok(())
}
