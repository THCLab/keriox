mod registry_round_trip;

use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError};
use tempfile::Builder;

#[async_std::test]
async fn a_registry_is_issued_and_revoked() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?;
    registry_round_trip::issue_and_revoke(&controller).await
}
