use std::sync::Arc;

use controller::{
    identifier_controller::IdentifierController, mailbox_updating::ActionRequired,
    utils::OptionalConfig, Controller,
};
use keri::{
    event_parsing::{codes::self_signing::SelfSigning, primitives::CesrPrimitive},
    oobi::{LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

#[actix_web::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config = OptionalConfig::init().with_db_path(root.into_path());

    let controller1 = Arc::new(Controller::new(Some(initial_config)).unwrap());

    let root2 = Builder::new().prefix("test-db").tempdir().unwrap();
    let initial_config2 = OptionalConfig::init().with_db_path(root2.into_path());
    let controller2 = Arc::new(Controller::new(Some(initial_config2)).unwrap());

    let km1 = CryptoBox::new()?;
    let km2 = CryptoBox::new()?;
    let witness_oobi = LocationScheme {
        eid: "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".parse()?,
        scheme: Scheme::Http,
        url: "http://127.0.0.1:3232".parse()?,
    };
    let witness_oobi_json = serde_json::to_string(&witness_oobi).unwrap();
    let witness_basic_prefix: BasicPrefix =
        "BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC".parse()?;

    let mut identifier1 = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller1
            .incept(vec![pk], vec![npk], vec![witness_oobi.clone()], 1)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller1
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();

        IdentifierController::new(incepted_identifier, controller1.clone())
    };

    // Quering mailbox to get receipts
    let query = identifier1.query_mailbox(&identifier1.id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    assert!(identifier1.get_kel().is_ok());

    let mut identifier2 = {
        let pk = BasicPrefix::Ed25519(km2.public_key());
        let npk = BasicPrefix::Ed25519(km2.next_public_key());

        let icp_event = controller2
            .incept(vec![pk], vec![npk], vec![witness_oobi], 1)
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller2
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await
            .unwrap();
        IdentifierController::new(incepted_identifier, controller2.clone())
    };
    // Quering mailbox to get receipts
    let query = identifier2.query_mailbox(&identifier2.id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        identifier2.finalize_query(vec![(qry, signature)]).await?;
    }

    let url = url::Url::parse("http://127.0.0.1:3236").unwrap();

    let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b"
        .parse()
        .unwrap();

    let watcher_oobi = LocationScheme {
        eid: IdentifierPrefix::Basic(watcher_id.clone()),
        scheme: keri::oobi::Scheme::Http,
        url,
    };

    println!("{}", serde_json::to_string(&watcher_oobi).unwrap());
    identifier1.source.resolve_loc_schema(&watcher_oobi).await?;

    let add_watcher = identifier1
        .add_watcher(IdentifierPrefix::Basic(watcher_id.clone()))
        .unwrap();

    println!("add_watcher: {}", add_watcher);
    let add_watcher_sig = SelfSigningPrefix::new(
        SelfSigning::Ed25519Sha512,
        km1.sign(add_watcher.as_bytes()).unwrap(),
    );

    identifier1
        .finalize_event(add_watcher.as_bytes(), add_watcher_sig)
        .await?;

    let oobi1 = r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://127.0.0.1:3232/"}"#;
    let oobi2 = format!(
        r#"{{"cid":"{}","role":"witness","eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC"}}"#,
        identifier2.id.clone().to_str()
    );

    identifier1
        .source
        .send_oobi_to_watcher(&identifier1.id, &oobi1)
        .await?;
    identifier1
        .source
        .send_oobi_to_watcher(&identifier1.id, &oobi2)
        .await?;

    let qry_watcher = identifier1.query_own_watchers(&identifier2.id)?;
    for qry in qry_watcher {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    let (group_inception, exn_messages) = identifier1.incept_group(
        vec![identifier2.id.clone()],
        2,
        Some(vec![witness_basic_prefix.clone()]),
        Some(1),
        None,
    )?;

    let signature_icp = SelfSigningPrefix::Ed25519Sha512(km1.sign(group_inception.as_bytes())?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(km1.sign(exn_messages[0].as_bytes())?);

    // Group initiator needs to use `finalize_group_incept` instead of just
    // `finalize_event`, to send multisig request to other group participants.
    // Identifier who get this request from mailbox, can use just `finalize_event`
    let group_id = identifier1
        .finalize_group_incept(
            group_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), signature_exn)],
        )
        .await?;

    let kel = controller1
        .storage
        .get_kel_messages_with_receipts(&group_id)?;
    // Event is not yet accepted.
    assert!(kel.is_none());

    // Quering mailbox to get multisig request
    let query = identifier2.query_mailbox(&identifier2.id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        let res = identifier2.finalize_query(vec![(qry, signature)]).await?;

        match &res[0] {
            ActionRequired::DelegationRequest(_, _) => {
                unreachable!()
            }
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(km2.sign(&multisig_event.serialize()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(km2.sign(&exn.serialize()?)?);
                identifier2
                    .finalize_group_incept(
                        &multisig_event.serialize()?,
                        signature_ixn.clone(),
                        vec![(exn.serialize()?, signature_exn)],
                    )
                    .await?;
            }
        };
    }

    // Query to get events signed by other participants
    let query = identifier1.query_mailbox(&group_id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    // Query to have receipt of group inception
    let query = identifier1.query_mailbox(&group_id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.serialize()?)?);
        identifier1.finalize_query(vec![(qry, signature)]).await?;
    }

    let group_state_1 = identifier1.source.storage.get_state(&group_id)?;
    assert_eq!(group_state_1.unwrap().sn, 0);

    let group_state_2 = identifier2.source.storage.get_state(&group_id)?;
    assert!(group_state_2.is_none());

    // Query to have receipt of group inception
    let query = identifier2.query_mailbox(&group_id, &[witness_basic_prefix.clone()])?;

    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(km2.sign(&qry.serialize()?)?);
        identifier2.finalize_query(vec![(qry, signature)]).await?;
    }

    let group_state_2 = identifier2.source.storage.get_state(&group_id)?;
    assert_eq!(group_state_2.unwrap().sn, 0);

    // println!("---------------------------");
    // let kel = identifier1.source.storage.get_kel_messages_with_receipts(&group_id);
    // println!("\n kel end: {:?}", kel);

    // let kel = identifier2.source.storage.get_kel_messages_with_receipts(&group_id);
    // println!("\n kel end: {:?}", kel);

    Ok(())
}
