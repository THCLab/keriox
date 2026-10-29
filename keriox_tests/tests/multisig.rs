use std::sync::Arc;

use anyhow::Result;
use keri_controller::{
    config::ControllerConfig, controller::Controller, identifier::mechanics::MechanicsError,
    mailbox_updating::ActionRequired, Oobi,
};
use keri_core::{
    actor::prelude::Message,
    oobi::{EndRole, Role},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use keri_tests::{collect_receipts, settings::InfrastructureContext};
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
    // Asking the witness for the KEL to get receipts
    let id1 = identifier1.id().clone();
    collect_receipts(&mut identifier1, &km1, &id1, &[witness_id.clone()]).await?;
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

    // Asking the witness for the KEL to get receipts
    let id2 = identifier2.id().clone();
    collect_receipts(&mut identifier2, &km2, &id2, &[witness_id.clone()]).await?;
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
        format!(
            r#"{{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"{}"}}"#,
            witness_oobi.url.as_ref().unwrap()
        ),
        serde_json::to_string(&witness_oobi).unwrap()
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
    // `finalize_event`: it returns the forwards that carry the multisig
    // request to the other group participants.
    let (group_id, forwards) = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;

    let kel = controller1.get_kel_with_receipts(&group_id);
    // Event is not yet accepted.
    assert!(kel.is_none());

    // identifier2 verifies the forward against identifier1's KEL.
    for notice in controller1.get_kel_with_receipts(&id1).unwrap() {
        controller2.known_events.save(&Message::Notice(notice))?;
    }

    // identifier2 receives the multisig request
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the other participant: {forwards:?}")
    };
    assert_eq!(&request.to, identifier2.id());
    let action_required = identifier2.receive_forwards(&request.message).await?;
    let signed_by_2 = match &action_required[0] {
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
                .await?
        }
    };

    // identifier1 receives the event signed by the other participant, for
    // the group, and publishes it fully signed.
    let [signed] = signed_by_2.as_slice() else {
        panic!("one forward, to the group: {signed_by_2:?}")
    };
    assert_eq!(signed.to, group_id);
    let action_required = identifier1.receive_forwards(&signed.message).await?;
    assert!(action_required.is_empty());

    // Query to have receipt of group inception
    collect_receipts(&mut identifier1, &km1, &group_id, &[witness_id.clone()]).await?;

    let group_state_1 = identifier1.find_state(&group_id)?;
    assert_eq!(group_state_1.sn, 0);

    let group_state_2 = identifier2.find_state(&group_id);
    assert!(matches!(
        group_state_2,
        Err(MechanicsError::UnknownIdentifierError(_))
    ));

    // Query to have receipt of group inception
    collect_receipts(&mut identifier2, &km2, &group_id, &[witness_id.clone()]).await?;

    let group_state_2 = identifier2.find_state(&group_id)?;
    assert_eq!(group_state_2.sn, 0);

    Ok(())
}
