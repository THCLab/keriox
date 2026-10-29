mod delegation_round_trip;

mod test_delegated_incept {
    use std::{collections::HashMap, sync::Arc};

    use keri_controller::{
        config::ControllerConfig, controller::Controller, error::ControllerError, LocationScheme,
    };
    use keri_core::{
        prefix::IdentifierPrefix,
        transport::test::{TestActorMap, TestTransport},
    };
    use tempfile::Builder;
    use url::Host;
    use witness::{WitnessEscrowConfig, WitnessListener};

    #[async_std::test]
    async fn test_delegated_incept() -> Result<(), ControllerError> {
        use url::Url;
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        let root2 = Builder::new().prefix("test-db2").tempdir().unwrap();

        // Setup test witness
        let witness = {
            let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
            let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
            Arc::new(
                WitnessListener::setup_with_redb(
                    url::Url::parse("http://witness1:3232/").unwrap(),
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

        // Setup delegatee and delegator controllers
        let delegatee_controller = Arc::new(Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            transport: Box::new(transport.clone()),
            ..Default::default()
        })?);
        let delegator_controller = Arc::new(Controller::new(ControllerConfig {
            db_path: root2.path().to_owned(),
            transport: Box::new(transport.clone()),
            ..Default::default()
        })?);

        super::delegation_round_trip::delegated_inception(
            &delegatee_controller,
            &delegator_controller,
            &wit_location,
        )
        .await
    }
}
