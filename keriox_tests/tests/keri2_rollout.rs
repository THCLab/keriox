//! The KERI 2.0 rollout switches writers one group at a time, so every mix
//! of versions it passes through has to work end to end: a signer incepts
//! and rotates with witness receipts, and a verifier finds the signer's KEL
//! through its watcher and checks a signature.
//!
//! - servers on 1.0, clients on 2.0: clients switched first;
//! - servers on 2.0, a client still on 1.0: an R1 client not switched yet;
//! - everything on 2.0.

use std::{sync::Arc, time::Duration};

use actix_rt::time::sleep;
use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier::query::QueryResponse,
    BasicPrefix, CryptoBox, EndRole, IdentifierPrefix, KeyManager, LocationScheme, Oobi,
    RedbController as Controller, RedbIdentifier as Identifier, SelfSigningPrefix,
};
use keri_core::event_message::keri_version::KeriVersion;
use keri_tests::settings::{InfrastructureContext, Keri2InfrastructureContext};
use tempfile::{Builder, TempDir};
use test_context::test_context;

struct Client {
    _db: TempDir,
    controller: Arc<Controller>,
    keys: CryptoBox,
    id: Identifier,
}

/// An identifier with both witnesses, its controller writing `version`,
/// incepted with the witnesses' receipts.
async fn incept(ctx: &InfrastructureContext, version: KeriVersion) -> Client {
    let (first_witness_id, first_witness_oobi) = ctx.first_witness_data();
    let (_, second_witness_oobi) = ctx.second_witness_data();
    let db = Builder::new().prefix("keri2-rollout").tempdir().unwrap();
    let controller = Arc::new(
        Controller::new(ControllerConfig {
            db_path: db.path().to_owned(),
            keri_version: version,
            ..Default::default()
        })
        .unwrap(),
    );
    let keys = CryptoBox::new().unwrap();
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            vec![first_witness_oobi, second_witness_oobi],
            1,
        )
        .await
        .unwrap();
    let expected = match version {
        KeriVersion::V1 => r#"{"v":"KERI10JSON"#,
        KeriVersion::V2 => r#"{"v":"KERICAACAAJSON"#,
    };
    assert!(icp.starts_with(expected), "{icp}");
    let signature = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes()).unwrap());
    let mut id = controller
        .finalize_incept(icp.as_bytes(), &signature)
        .unwrap();
    id.notify_witnesses().await.unwrap();
    collect_receipts(&mut id, &keys, &first_witness_id).await;
    Client {
        _db: db,
        controller,
        keys,
        id,
    }
}

async fn collect_receipts(id: &mut Identifier, keys: &CryptoBox, witness: &BasicPrefix) {
    for qry in id.query_mailbox(id.id(), &[witness.clone()]).unwrap() {
        let signature =
            SelfSigningPrefix::Ed25519Sha512(keys.sign(&qry.encode().unwrap()).unwrap());
        id.finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }
}

/// The verifier's watcher knows the witnesses and where the signer's KEL is.
async fn watch(ctx: &InfrastructureContext, verifier: &mut Client, signer: &IdentifierPrefix) {
    let (watcher_id, watcher_oobi) = ctx.watcher_data();
    let (second_witness_id, _) = ctx.second_witness_data();
    verifier
        .id
        .resolve_oobi(&Oobi::Location(watcher_oobi))
        .await
        .unwrap();
    let add_watcher = verifier
        .id
        .add_watcher(IdentifierPrefix::Basic(watcher_id))
        .unwrap();
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier.keys.sign(add_watcher.as_bytes()).unwrap());
    verifier
        .id
        .finalize_add_watcher(add_watcher.as_bytes(), signature)
        .await
        .unwrap();
    let witnesses: [LocationScheme; 2] = [ctx.first_witness_data().1, ctx.second_witness_data().1];
    for oobi in witnesses.map(Oobi::Location) {
        verifier.id.resolve_oobi(&oobi).await.unwrap();
        verifier
            .id
            .send_oobi_to_watcher(verifier.id.id(), &oobi)
            .await
            .unwrap();
    }
    let signer_oobi = EndRole {
        cid: signer.clone(),
        role: keri_core::oobi::Role::Witness,
        eid: IdentifierPrefix::Basic(second_witness_id),
    };
    verifier
        .id
        .send_oobi_to_watcher(verifier.id.id(), &Oobi::EndRole(signer_oobi))
        .await
        .unwrap();
}

/// Asks the verifier's watcher for the signer's KEL until it has it.
async fn query(verifier: &mut Client, signer: &Identifier) -> QueryResponse {
    let seal = signer.get_last_event_seal().unwrap();
    let queries: Vec<_> = verifier
        .id
        .query_watchers(&seal)
        .unwrap()
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(
                verifier.keys.sign(&qry.encode().unwrap()).unwrap(),
            );
            (qry, signature)
        })
        .collect();
    for _ in 0..40 {
        let (response, errors) = verifier.id.finalize_query(queries.clone()).await;
        if errors.is_empty() {
            return response;
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("the watcher never returned the signer's KEL");
}

async fn rollout_mix(
    ctx: &InfrastructureContext,
    signer_version: KeriVersion,
    verifier_version: KeriVersion,
) -> Result<(), ControllerError> {
    let mut signer = incept(ctx, signer_version).await;
    let mut verifier = incept(ctx, verifier_version).await;
    watch(ctx, &mut verifier, signer.id.id()).await;
    assert_eq!(
        query(&mut verifier, &signer.id).await,
        QueryResponse::Updates
    );

    let message = b"hello";
    let signature = signer.id.sign_data(
        message,
        &[SelfSigningPrefix::Ed25519Sha512(
            signer.keys.sign(message).unwrap(),
        )],
    )?;
    verifier.controller.verify(message, &signature).unwrap();

    // The signer rotates; the verifier sees it through the watcher.
    signer.keys.rotate()?;
    let rot = signer
        .id
        .rotate(
            vec![BasicPrefix::Ed25519(signer.keys.public_key())],
            vec![BasicPrefix::Ed25519(signer.keys.next_public_key())],
            1,
            vec![],
            vec![],
            1,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(signer.keys.sign(rot.as_bytes()).unwrap());
    signer.id.finalize_rotate(rot.as_bytes(), signature).await?;
    signer.id.notify_witnesses().await?;
    let (first_witness_id, _) = ctx.first_witness_data();
    collect_receipts(&mut signer.id, &signer.keys, &first_witness_id).await;
    assert_eq!(signer.controller.find_state(signer.id.id())?.sn, 1);

    let mut response = query(&mut verifier, &signer.id).await;
    for _ in 0..40 {
        if verifier.controller.find_state(signer.id.id())?.sn == 1 {
            break;
        }
        sleep(Duration::from_millis(250)).await;
        response = query(&mut verifier, &signer.id).await;
    }
    let _ = response;
    assert_eq!(verifier.controller.find_state(signer.id.id())?.sn, 1);
    Ok(())
}

/// Rotates `id` to the next keys in its controller's KERI version and
/// collects the first witness's receipt. Returns the rotation event.
async fn rotate(
    ctx: &InfrastructureContext,
    id: &mut Identifier,
    keys: &mut CryptoBox,
) -> Result<String, ControllerError> {
    keys.rotate()?;
    let rot = id
        .rotate(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            1,
            vec![],
            vec![],
            1,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(keys.sign(rot.as_bytes()).unwrap());
    id.finalize_rotate(rot.as_bytes(), signature).await?;
    id.notify_witnesses().await?;
    let (first_witness_id, _) = ctx.first_witness_data();
    collect_receipts(id, keys, &first_witness_id).await;
    Ok(rot)
}

/// An identifier incepted in KERI 1.0 whose controller restarts writing
/// KERI 2.0: its next rotation is a 2.0 event on a 1.0 log, and a verifier
/// still on 1.0 must see it through its watcher.
#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn a_keri_1_identifier_rotates_in_keri_2(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let signer = incept(ctx, KeriVersion::V1).await;
    let mut verifier = incept(ctx, KeriVersion::V1).await;
    watch(ctx, &mut verifier, signer.id.id()).await;
    assert_eq!(
        query(&mut verifier, &signer.id).await,
        QueryResponse::Updates
    );

    // The signer's controller restarts on the same database writing 2.0.
    let Client {
        _db: db,
        controller,
        mut keys,
        id,
    } = signer;
    let prefix = id.id().clone();
    drop(id);
    drop(controller);
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: db.path().to_owned(),
        keri_version: KeriVersion::V2,
        ..Default::default()
    })?);
    let mut id = Identifier::new(
        prefix,
        None,
        controller.known_events.clone(),
        controller.communication.clone(),
        controller.cache.clone(),
    );

    // The verifier's watcher already holds the signer's log; it has to
    // catch up with the events that follow, not only fetch from scratch.
    for sn in 1..=2 {
        let rot = rotate(ctx, &mut id, &mut keys).await?;
        assert!(rot.starts_with(r#"{"v":"KERICAACAAJSON"#), "{rot}");
        assert_eq!(controller.find_state(id.id())?.sn, sn);
        for _ in 0..40 {
            query(&mut verifier, &id).await;
            if verifier.controller.find_state(id.id())?.sn == sn {
                break;
            }
            sleep(Duration::from_millis(250)).await;
        }
        assert_eq!(verifier.controller.find_state(id.id())?.sn, sn);
    }
    Ok(())
}

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn keri_2_clients_with_keri_1_servers(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    rollout_mix(ctx, KeriVersion::V2, KeriVersion::V2).await
}

#[test_context(Keri2InfrastructureContext)]
#[actix_rt::test]
async fn a_keri_1_client_with_keri_2_servers(
    ctx: &mut Keri2InfrastructureContext,
) -> Result<(), ControllerError> {
    rollout_mix(&ctx.0, KeriVersion::V1, KeriVersion::V2).await?;
    rollout_mix(&ctx.0, KeriVersion::V2, KeriVersion::V1).await
}

#[test_context(Keri2InfrastructureContext)]
#[actix_rt::test]
async fn everything_on_keri_2(ctx: &mut Keri2InfrastructureContext) -> Result<(), ControllerError> {
    rollout_mix(&ctx.0, KeriVersion::V2, KeriVersion::V2).await
}
