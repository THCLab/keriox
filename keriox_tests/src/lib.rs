use std::{path::Path, sync::Arc, time::Duration};

use keri_controller::{
    config::ControllerConfig,
    error::ControllerError,
    identifier::{mechanics::forwards::Forward, Identifier},
    mailbox_updating::ActionRequired,
    registry::RegistryStore,
    BasicPrefix, CryptoBox, IdentifierPrefix, KeyManager, LocationScheme, RedbController,
    RedbIdentifier, SelfSigningPrefix,
};
use keri_core::{
    actor::error::ActorError,
    database::{EscrowCreator, EventDatabase},
    mailbox::exchange::{Exchange, ForwardTopic},
    oobi_manager::storage::OobiStorageBackend,
    prefix::IndexedSignature,
    transport::test::TestTransport,
};
use said::{derivation::HashFunctionCode, sad::SerializationFormats};

pub mod settings;

/// Waits before asking a watcher or witness again, as it may not have
/// caught up yet. Panics after 30 attempts, so a peer that never answers
/// fails the test instead of hanging it.
pub async fn wait_before_retry(attempts: &mut u32, what: &str) {
    *attempts += 1;
    assert!(*attempts <= 30, "{what}: no answer after 30 attempts");
    actix_rt::time::sleep(Duration::from_millis(500)).await;
}

// Helper function that incepts identifier
pub async fn setup_identifier(
    root_path: &Path,
    witness_locations: Vec<LocationScheme>,
    transport: Option<TestTransport<ActorError>>,
) -> (RedbIdentifier, CryptoBox, Arc<RedbController>) {
    let verifier_controller = Arc::new(
        match transport {
            None => RedbController::new(ControllerConfig {
                db_path: root_path.to_owned(),
                ..Default::default()
            }),
            Some(transport) => RedbController::new(ControllerConfig {
                db_path: root_path.to_owned(),
                transport: Box::new(transport.clone()),
                ..Default::default()
            }),
        }
        .unwrap(),
    );

    let witnesses_id: Vec<BasicPrefix> = witness_locations
        .iter()
        .map(|loc| match &loc.eid {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => unreachable!(),
        })
        .collect();

    let verifier_keypair = CryptoBox::new().unwrap();

    let pk = BasicPrefix::Ed25519NT(verifier_keypair.public_key());
    let npk = BasicPrefix::Ed25519NT(verifier_keypair.next_public_key());

    let icp_event = verifier_controller
        .incept(vec![pk], vec![npk], witness_locations, 1)
        .await
        .unwrap();
    let signature =
        SelfSigningPrefix::Ed25519Sha512(verifier_keypair.sign(icp_event.as_bytes()).unwrap());

    let mut verifier = verifier_controller
        .finalize_incept(icp_event.as_bytes(), &signature)
        .unwrap();

    assert_eq!(verifier.notify_witnesses().await.unwrap(), 1);

    // Asking the witnesses for the KEL to get receipts
    let verifier_id = verifier.id().clone();
    collect_receipts(
        &mut verifier,
        &verifier_keypair,
        &verifier_id,
        &witnesses_id,
    )
    .await
    .unwrap();
    (verifier, verifier_keypair, verifier_controller)
}

/// Collects `about`'s receipts (`about` is `id` itself or a group it is a
/// member of) by asking `witnesses` for its KEL, signing with `keypair`.
pub async fn collect_receipts<D, T, S>(
    id: &mut Identifier<D, T, S>,
    keypair: &CryptoBox,
    about: &IdentifierPrefix,
    witnesses: &[BasicPrefix],
) -> Result<(), ControllerError>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    let queries = id
        .query_receipts(about, witnesses)?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(keypair.sign(&qry.encode()?)?);
            Ok((qry, signature))
        })
        .collect::<Result<Vec<_>, ControllerError>>()?;
    id.finalize_query_receipts(queries).await?;
    Ok(())
}

/// Lets a member of the delegator group `delegator_group_id` handle the
/// `forwards` delivered to it: co-signs the group events it is asked to
/// and approves the delegation request. Returns the forwards to deliver in
/// turn: the signed group events, for the other members, and the approval,
/// for the delegatee.
pub async fn handle_delegation_request(
    id: &mut RedbIdentifier,
    keypair: &CryptoBox,
    witness_id: &[BasicPrefix],
    delegator_group_id: IdentifierPrefix,
    delegatee_id: &IdentifierPrefix,
    forwards: &[u8],
) -> Result<Vec<Forward>, ControllerError> {
    let mut to_deliver = vec![];
    for ar in id.receive_forwards(forwards).await? {
        match &ar {
            ActionRequired::MultisigRequest(multisig_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(keypair.sign(&multisig_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn.encode()?)?);
                let kc = id.find_state(id.id()).unwrap().current;
                let index = id.index_in_current_keys(&kc)?;
                let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                to_deliver.extend(
                    id.finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await?,
                );
            }
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn =
                    SelfSigningPrefix::Ed25519Sha512(keypair.sign(&delegating_event.encode()?)?);
                let signature_exn = SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn.encode()?)?);
                let kc = id.find_state(id.id()).unwrap().current;
                let index = id.index_in_current_keys(&kc)?;
                let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                to_deliver.extend(
                    id.finalize_group_event(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await?,
                );
                id.notify_witnesses().await?;

                // Query for receipts
                collect_receipts(id, keypair, &delegator_group_id, witness_id).await?;

                let kc = id.find_state(&delegator_group_id).unwrap().current;
                let index = id.index_in_current_keys(&kc).unwrap();
                // send accepted event to child
                let exn_message = Exchange::forward(
                    &delegatee_id,
                    ForwardTopic::Delegate,
                    &delegating_event.encode()?,
                )
                .to_message(
                    &id.id(),
                    &delegatee_id,
                    SerializationFormats::JSON,
                    HashFunctionCode::Blake3_256,
                );
                let signature_exn =
                    SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn_message.encode()?)?);

                let data_signature = IndexedSignature::new_both_same(signature_ixn, index as u16);

                let kc = id.find_state(&id.id()).unwrap().current;
                let index = id.index_in_current_keys(&kc).unwrap();
                let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                to_deliver.push(id.finalize_exchange(
                    &exn_message.encode()?,
                    exn_index_signature,
                    &delegating_event,
                    data_signature,
                )?);
            }
        };
    }
    Ok(to_deliver)
}
