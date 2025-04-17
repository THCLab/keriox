use std::sync::Arc;

use anyhow::Result;
use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::mechanics::MechanicsError,
    mailbox_updating::ActionRequired, Oobi,
};
use keri_core::{
    oobi::{EndRole, Role},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use keri_tests::settings::InfrastructureContext;
use tempfile::Builder;
use test_context::test_context;

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn test_multisig(ctx: &mut InfrastructureContext) -> Result<()> {
    let (witness_id, witness_oobi) = ctx.first_witness_data();
    let (watcher_id, watcher_oobi) = ctx.watcher_data();

    // Setup first identifier.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller1 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root.path().to_owned(),
            ..Default::default()
        })
        .unwrap(),
    );

    let km1 = CryptoBox::new()?;
    let pk = BasicPrefix::Ed25519(km1.public_key());
    let npk = BasicPrefix::Ed25519(km1.next_public_key());

    let icp_event = controller1
        .incept(vec![pk], vec![npk], vec![witness_oobi.clone()], 1)
        .await
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

    let mut identifier1 = controller1
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();

    identifier1.notify_witnesses().await?;
    // Quering mailbox to get receipts
    let query = identifier1.query_mailbox(identifier1.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }
    assert!(identifier1.get_own_kel().is_some());

    // Setup second identifier.
    let root2 = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller2 = Arc::new(
        Controller::new(ControllerConfig {
            db_path: root2.path().to_owned(),
            ..Default::default()
        })
        .unwrap(),
    );
    let km2 = CryptoBox::new()?;

    let pk = BasicPrefix::Ed25519(km2.public_key());
    let npk = BasicPrefix::Ed25519(km2.next_public_key());

    let icp_event = controller2
        .incept(vec![pk], vec![npk], vec![witness_oobi.clone()], 1)
        .await
        .unwrap();
    let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

    let mut identifier2 = controller2
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();
    identifier2.notify_witnesses().await?;

    // Quering mailbox to get receipts
    let query = identifier2.query_mailbox(identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }
    assert!(identifier2.get_own_kel().is_some());

    // Identifier1 adds watcher
    identifier1
        .resolve_oobi(&Oobi::Location(watcher_oobi.clone()))
        .await?;

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();

    println!("add_watcher: {}", add_watcher);
    let add_watcher_sig = SelfSigningPrefix::Ed25519Sha512(km1.sign(add_watcher.as_bytes())?);

    identifier1
        .finalize_add_watcher(add_watcher.as_bytes(), add_watcher_sig)
        .await?;
    assert_eq!(
        identifier1.watchers()?,
        vec![IdentifierPrefix::Basic(watcher_id)]
    );

    // Send identifier2 oobis to identifier1's watchers and query for results.
    assert_eq!(
        r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#,
        &serde_json::to_string(&witness_oobi).unwrap()
    );
    let oobi2 = EndRole {
        cid: identifier2.id().clone(),
        role: Role::Witness,
        eid: IdentifierPrefix::Basic(witness_id.clone()),
    };

    identifier1
        .send_oobi_to_watcher(&identifier1.id(), &Oobi::Location(witness_oobi))
        .await?;
    identifier1
        .send_oobi_to_watcher(&identifier1.id(), &Oobi::EndRole(oobi2))
        .await?;

    let qry_watcher =
        identifier1.query_watchers(&identifier2.get_last_establishment_event_seal()?)?;
    for qry in qry_watcher {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await;
    }

    // Incept group
    let (group_inception, exn_messages) = identifier1.incept_group(
        vec![identifier2.id().clone()],
        2,
        Some(2),
        Some(vec![witness_id.clone()]),
        Some(1),
        None,
    )?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);
    let exn_index_signature = identifier1.sign_with_index(signature_exn, 0)?;

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = controller1.get_kel_with_receipts(&group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Quering mailbox to get multisig request
    let query = identifier2.query_mailbox(&identifier2.id(), &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        let action_required = identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;

        match &action_required[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&multisig_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.encode()?)?);
                let exn_index_signature = identifier2.sign_with_index(signature_exn, 0)?;
                identifier2
                    .finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = identifier1.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    // Query to have receipt of group inception
    let query = identifier1.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        identifier1
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_1 = identifier1.find_state(&group_id)?;
    assert_eq!(group_state_1.sn, 0);

    let group_state_2 = identifier2.find_state(&group_id);
    assert!(matches!(
        group_state_2,
        Err(MechanicsError::UnknownIdentifierError(_))
    ));

    // Query to have receipt of group inception
    let query = identifier2.query_mailbox(&group_id, &[witness_id.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.encode()?)?);
        identifier2
            .finalize_query_mailbox(vec![(qry, signature)])
            .await?;
    }

    let group_state_2 = identifier2.find_state(&group_id)?;
    assert_eq!(group_state_2.sn, 0);

    Ok(())
}
