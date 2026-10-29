mod delegation_round_trip;

mod test_delegated_incept_postgres {
    mod common {
        include!("common/mod.rs");
    }

    use std::{collections::HashMap, sync::Arc};

    use keri_controller::{
        config::ControllerConfig, controller::PostgresController, error::ControllerError, LocationScheme,
    };
    use keri_core::{
        prefix::IdentifierPrefix,
        transport::test::{TestActorMap, TestTransport},
    };
    use tempfile::Builder;
    use url::Host;
    use witness::{WitnessEscrowConfig, WitnessListener};

    #[async_std::test]
    async fn test_delegated_incept_postgres() -> Result<(), ControllerError> {
        use url::Url;

        common::ensure_clean_db();

        // Setup test witness (redb-backed — witness storage backend is independent)
        let witness = {
            let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
            let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup_with_redb(
                    Url::parse("http://witness1:3232/").unwrap(),
                    witness_root.path(),
                    Some(seed.to_string()),
                    WitnessEscrowConfig::default(),
                    keri_core::event_message::keri_version::KeriVersion::V1_0,
                )
                .unwrap(),
            )
        };

        let witness_id_basic = witness.get_prefix();
        let witness_id = IdentifierPrefix::Basic(witness_id_basic.clone());
        assert_eq!(
            witness_id.to_string(),
            "BErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q"
        );
        let wit_location = LocationScheme {
            eid: witness_id,
            scheme: keri_core::oobi::Scheme::Http,
            url: Some(Url::parse("http://witness1:3232").unwrap()),
        };

        let mut actors: TestActorMap = HashMap::new();
        actors.insert((Host::Domain("witness1".to_string()), 3232), witness);
        let transport = TestTransport::new(actors);

        let delegatee_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let delegator_root = Builder::new().prefix("test-db2").tempdir().unwrap();

        // Setup delegatee and delegator controllers
        let delegatee_controller = Arc::new(
            PostgresController::new_postgres(
                &common::get_database_url(),
                ControllerConfig {
                    db_path: delegatee_root.path().to_owned(),
                    transport: Box::new(transport.clone()),
                    ..Default::default()
                },
            )
            .await?,
        );
        let delegator_controller = Arc::new(
            PostgresController::new_postgres(
                &common::get_database_url(),
                ControllerConfig {
                    db_path: delegator_root.path().to_owned(),
                    transport: Box::new(transport.clone()),
                    ..Default::default()
                },
            )
            .await?,
        );

        super::delegation_round_trip::delegated_inception(
            &delegatee_controller,
            &delegator_controller,
            &wit_location,
        )
        .await
    }
}
