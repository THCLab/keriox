//! Removing a watcher: the `end_role_cut` reply that `remove_watcher`
//! generates is finalized like an `end_role_add`, so the watcher is no
//! longer listed and learns that it was cut.

use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, error::ControllerError, BasicPrefix, CryptoBox, IdentifierPrefix,
    KeyManager, Oobi, RedbController, SelfSigningPrefix,
};
use keri_tests::settings::InfrastructureContext;
use tempfile::Builder;
use test_context::test_context;

fn sign(km: &CryptoBox, data: &[u8]) -> SelfSigningPrefix {
    SelfSigningPrefix::Ed25519Sha512(km.sign(data).unwrap())
}

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn a_removed_watcher_is_no_longer_listed(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Arc::new(RedbController::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);
    let km = CryptoBox::new()?;
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            vec![],
            0,
        )
        .await?;
    let id = controller.finalize_incept(icp.as_bytes(), &sign(&km, icp.as_bytes()))?;

    let (watcher_id, watcher) = ctx.watcher_data();
    let watcher_id = IdentifierPrefix::Basic(watcher_id);
    id.resolve_oobi(&Oobi::Location(watcher)).await?;
    let add = id.add_watcher(watcher_id.clone())?;
    id.finalize_add_watcher(add.as_bytes(), sign(&km, add.as_bytes()))
        .await?;
    assert_eq!(id.watchers()?, vec![watcher_id.clone()]);

    let cut = id.remove_watcher(watcher_id)?;
    id.finalize_add_watcher(cut.as_bytes(), sign(&km, cut.as_bytes()))
        .await?;

    assert!(id.watchers()?.is_empty());
    Ok(())
}
