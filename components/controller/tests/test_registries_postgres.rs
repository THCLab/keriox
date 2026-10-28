mod common;
mod registry_round_trip;

use keri_controller::{
    config::ControllerConfig, controller::PostgresController, error::ControllerError,
};
use tempfile::Builder;

#[async_std::test]
async fn a_registry_is_issued_and_revoked_in_postgres() -> Result<(), ControllerError> {
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
    registry_round_trip::issue_and_revoke(&controller).await
}
