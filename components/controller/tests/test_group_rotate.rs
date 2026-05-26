use std::sync::Arc;

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError, RedbIdentifier,
};
use keri_core::{
    prefix::{BasicPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

type TestController = Controller<
    keri_core::database::redb::RedbDatabase,
    teliox::database::redb::RedbTelDatabase,
    keri_core::oobi_manager::storage::RedbOobiStorage,
>;

/// Single-signer round-trip: 1-of-2 group, A rotates the group to drop B.
#[async_std::test]
async fn test_rotate_group_evicts_member() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("test-rotate-group").tempdir().unwrap();
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);

    let mut km_a = CryptoBox::new()?;
    let mut km_b = CryptoBox::new()?;
    let mut id_a = incept_local(&controller, &km_a).await?;
    let mut id_b = incept_local(&controller, &km_b).await?;

    let group_id = create_1of2_group(&mut id_a, &km_a, &mut id_b, &km_b).await?;

    rotate_local(&mut id_a, &mut km_a).await?;
    rotate_local(&mut id_b, &mut km_b).await?;

    let (rot, rot_exns) = id_a
        .rotate_group(
            &group_id,
            vec![id_a.id().clone()],
            1,
            Some(1),
            vec![],
            vec![],
            None,
        )
        .await?;
    assert!(rot_exns.is_empty(), "no other members → no exchanges");

    let sig_rot_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(rot.as_bytes())?);
    id_a
        .finalize_group_event(rot.as_bytes(), sig_rot_a, vec![])
        .await?;

    let group_state = controller.find_state(&group_id).expect("group state");
    assert_eq!(group_state.sn, 1, "rot bumps sn to 1");
    assert_eq!(group_state.current.public_keys.len(), 1);
    let new_pk_a = BasicPrefix::Ed25519(km_a.public_key());
    assert_eq!(group_state.current.public_keys[0], new_pk_a);

    Ok(())
}

/// Multi-party round-trip: 2-of-3, A rotates the group down to {A, B}.
#[async_std::test]
async fn test_rotate_group_multi_party() -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-rotate-group-multi")
        .tempdir()
        .unwrap();
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);

    let mut km_a = CryptoBox::new()?;
    let mut km_b = CryptoBox::new()?;
    let mut km_c = CryptoBox::new()?;
    let mut id_a = incept_local(&controller, &km_a).await?;
    let mut id_b = incept_local(&controller, &km_b).await?;
    let mut id_c = incept_local(&controller, &km_c).await?;

    let (icp, exns) = id_a.incept_group(
        vec![id_b.id().clone(), id_c.id().clone()],
        2,
        Some(2),
        None,
        None,
        None,
    )?;
    let sig_icp_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(icp.as_bytes())?);
    let mut exn_pairs = Vec::with_capacity(exns.len());
    for exn in &exns {
        let sig_exn = SelfSigningPrefix::Ed25519Sha512(km_a.sign(exn.as_bytes())?);
        let exn_sig = id_a.sign_with_index(sig_exn, 0)?;
        exn_pairs.push((exn.as_bytes().to_vec(), exn_sig));
    }
    let group_id = id_a
        .finalize_group_incept(icp.as_bytes(), sig_icp_a, exn_pairs)
        .await?;
    let sig_icp_b = SelfSigningPrefix::Ed25519Sha512(km_b.sign(icp.as_bytes())?);
    id_b
        .finalize_group_event(icp.as_bytes(), sig_icp_b, vec![])
        .await?;
    let sig_icp_c = SelfSigningPrefix::Ed25519Sha512(km_c.sign(icp.as_bytes())?);
    id_c
        .finalize_group_event(icp.as_bytes(), sig_icp_c, vec![])
        .await?;
    assert!(controller.get_kel_with_receipts(&group_id).is_some());

    rotate_local(&mut id_a, &mut km_a).await?;
    rotate_local(&mut id_b, &mut km_b).await?;
    rotate_local(&mut id_c, &mut km_c).await?;

    let (rot, rot_exns) = id_a
        .rotate_group(
            &group_id,
            vec![id_a.id().clone(), id_b.id().clone()],
            1,
            Some(1),
            vec![],
            vec![],
            None,
        )
        .await?;
    assert_eq!(rot_exns.len(), 1, "one forward exchange addressed to B");

    let sig_rot_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(rot.as_bytes())?);
    let sig_rot_exn_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(rot_exns[0].as_bytes())?);
    let rot_exn_sig_a = id_a.sign_with_index(sig_rot_exn_a, 0)?;
    id_a
        .finalize_group_event(
            rot.as_bytes(),
            sig_rot_a,
            vec![(rot_exns[0].as_bytes().to_vec(), rot_exn_sig_a)],
        )
        .await?;

    let sig_rot_b = SelfSigningPrefix::Ed25519Sha512(km_b.sign(rot.as_bytes())?);
    id_b
        .finalize_group_event(rot.as_bytes(), sig_rot_b, vec![])
        .await?;

    let group_state = controller.find_state(&group_id).expect("group state");
    assert_eq!(group_state.sn, 1);
    assert_eq!(group_state.current.public_keys.len(), 2);
    let new_pk_a = BasicPrefix::Ed25519(km_a.public_key());
    let new_pk_b = BasicPrefix::Ed25519(km_b.public_key());
    let new_pk_c = BasicPrefix::Ed25519(km_c.public_key());
    assert!(group_state.current.public_keys.contains(&new_pk_a));
    assert!(group_state.current.public_keys.contains(&new_pk_b));
    assert!(!group_state.current.public_keys.contains(&new_pk_c));

    Ok(())
}

/// No-op key refresh: same member set, fresh keys.
#[async_std::test]
async fn test_rotate_group_noop_refresh() -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-rotate-group-noop")
        .tempdir()
        .unwrap();
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);

    let mut km_a = CryptoBox::new()?;
    let mut km_b = CryptoBox::new()?;
    let mut id_a = incept_local(&controller, &km_a).await?;
    let mut id_b = incept_local(&controller, &km_b).await?;

    let group_id = create_1of2_group(&mut id_a, &km_a, &mut id_b, &km_b).await?;

    let group_pre = controller.find_state(&group_id).unwrap();
    let old_keys = group_pre.current.public_keys.clone();

    rotate_local(&mut id_a, &mut km_a).await?;
    rotate_local(&mut id_b, &mut km_b).await?;

    let (rot, _) = id_a
        .rotate_group(
            &group_id,
            vec![id_a.id().clone(), id_b.id().clone()],
            1,
            Some(1),
            vec![],
            vec![],
            None,
        )
        .await?;
    let sig_rot_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(rot.as_bytes())?);
    id_a
        .finalize_group_event(rot.as_bytes(), sig_rot_a, vec![])
        .await?;

    let group_post = controller.find_state(&group_id).unwrap();
    assert_eq!(group_post.sn, 1);
    assert_eq!(group_post.current.public_keys.len(), 2);
    assert_ne!(group_post.current.public_keys, old_keys);

    Ok(())
}

/// Threshold and membership violations are rejected.
#[async_std::test]
async fn test_rotate_group_threshold_violations() -> Result<(), ControllerError> {
    let root = Builder::new()
        .prefix("test-rotate-group-thresh")
        .tempdir()
        .unwrap();
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);

    let mut km_a = CryptoBox::new()?;
    let mut km_b = CryptoBox::new()?;
    let km_outsider = CryptoBox::new()?;
    let mut id_a = incept_local(&controller, &km_a).await?;
    let mut id_b = incept_local(&controller, &km_b).await?;
    let id_outsider = incept_local(&controller, &km_outsider).await?;

    let group_id = create_1of2_group(&mut id_a, &km_a, &mut id_b, &km_b).await?;

    rotate_local(&mut id_a, &mut km_a).await?;
    rotate_local(&mut id_b, &mut km_b).await?;

    let r0 = id_a
        .rotate_group(
            &group_id,
            vec![id_a.id().clone()],
            0,
            Some(0),
            vec![],
            vec![],
            None,
        )
        .await;
    assert!(r0.is_err(), "threshold 0 must be rejected");

    let r_high = id_a
        .rotate_group(
            &group_id,
            vec![id_a.id().clone()],
            2,
            Some(1),
            vec![],
            vec![],
            None,
        )
        .await;
    assert!(r_high.is_err(), "threshold above member count rejected");

    let r_outsider = id_outsider
        .rotate_group(
            &group_id,
            vec![id_outsider.id().clone()],
            1,
            Some(1),
            vec![],
            vec![],
            None,
        )
        .await;
    assert!(r_outsider.is_err(), "non-member rejected");

    Ok(())
}

// ── helpers ──────────────────────────────────────────────────────────────────

async fn incept_local(
    controller: &Arc<TestController>,
    km: &CryptoBox,
) -> Result<RedbIdentifier, ControllerError> {
    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());
    let icp = controller.incept(vec![pk], vec![npk], vec![], 0).await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(icp.as_bytes())?);
    controller.finalize_incept(icp.as_bytes(), &sig)
}

async fn rotate_local(
    id: &mut RedbIdentifier,
    km: &mut CryptoBox,
) -> Result<(), ControllerError> {
    km.rotate()?;
    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());
    let rot = id.rotate(vec![pk], vec![npk], 1, vec![], vec![], 0).await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(rot.as_bytes())?);
    id.finalize_rotate(rot.as_bytes(), sig).await?;
    Ok(())
}

async fn create_1of2_group(
    id_a: &mut RedbIdentifier,
    km_a: &CryptoBox,
    id_b: &mut RedbIdentifier,
    km_b: &CryptoBox,
) -> Result<keri_core::prefix::IdentifierPrefix, ControllerError> {
    let (icp, exns) = id_a.incept_group(
        vec![id_b.id().clone()],
        1,
        Some(1),
        None,
        None,
        None,
    )?;
    let sig_icp_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(icp.as_bytes())?);
    let sig_exn_a = SelfSigningPrefix::Ed25519Sha512(km_a.sign(exns[0].as_bytes())?);
    let exn_sig_a = id_a.sign_with_index(sig_exn_a, 0)?;
    let group_id = id_a
        .finalize_group_incept(
            icp.as_bytes(),
            sig_icp_a,
            vec![(exns[0].as_bytes().to_vec(), exn_sig_a)],
        )
        .await?;
    let sig_icp_b = SelfSigningPrefix::Ed25519Sha512(km_b.sign(icp.as_bytes())?);
    id_b
        .finalize_group_event(icp.as_bytes(), sig_icp_b, vec![])
        .await?;
    Ok(group_id)
}
