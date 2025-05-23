use std::{path::Path, sync::Arc};

use keri_controller::{
    config::ControllerConfig, controller::Controller, error::ControllerError,
    identifier::Identifier, mailbox_updating::ActionRequired, BasicPrefix, CryptoBox,
    IdentifierPrefix, KeyManager, LocationScheme, SelfSigningPrefix,
};
use keri_core::{
    actor::error::ActorError,
    mailbox::exchange::{Exchange, ForwardTopic, FwdArgs},
    prefix::IndexedSignature,
    transport::test::TestTransport,
};
use said::{derivation::HashFunctionCode, sad::SerializationFormats};
use transport::TelTestTransport;

pub mod settings;
pub mod transport;

// Helper function that incepts identifier
pub async fn setup_identifier(
    root_path: &Path,
    witness_locations: Vec<LocationScheme>,
    transport: Option<TestTransport<ActorError>>,
    tel_transport: Option<TelTestTransport>,
) -> (Identifier, CryptoBox, Arc<Controller>) {
    let verifier_controller = Arc::new(
        match (transport, tel_transport) {
            (None, None) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                ..Default::default()
            }),
            (None, Some(tel_transport)) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                tel_transport: Box::new(tel_transport.clone()),
                ..Default::default()
            }),
            (Some(transport), None) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                transport: Box::new(transport.clone()),
                ..Default::default()
            }),
            (Some(transport), Some(tel_transport)) => Controller::new(ControllerConfig {
                db_path: root_path.to_owned(),
                transport: Box::new(transport.clone()),
                tel_transport: Box::new(tel_transport.clone()),
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

    // Querying mailbox to get receipts
    for qry in verifier
        .query_mailbox(verifier.id(), &witnesses_id)
        .unwrap()
    {
        let signature = SelfSigningPrefix::Ed25519Sha512(
            verifier_keypair.sign(&qry.encode().unwrap()).unwrap(),
        );
        let _act = verifier
            .finalize_query_mailbox(vec![(qry, signature)])
            .await
            .unwrap();
    }
    (verifier, verifier_keypair, verifier_controller)
}

pub async fn handle_delegation_request(
    id: &mut Identifier,
    keypair: &CryptoBox,
    witness_id: &[BasicPrefix],
    delegator_group_id: IdentifierPrefix,
    delegatee_id: &IdentifierPrefix,
) -> Result<(), ControllerError> {
    let query = id.query_mailbox(&delegator_group_id, witness_id)?;
    for qry in query {
        let signature = SelfSigningPrefix::Ed25519Sha512(keypair.sign(&qry.encode()?)?);
        let ar = id.finalize_query_mailbox(vec![(qry, signature)]).await?;

        for ar in ar {
            match &ar {
                ActionRequired::MultisigRequest(multisig_event, exn) => {
                    let signature_ixn =
                        SelfSigningPrefix::Ed25519Sha512(keypair.sign(&multisig_event.encode()?)?);
                    let signature_exn =
                        SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn.encode()?)?);
                    let kc = id.find_state(id.id()).unwrap().current;
                    let index = id.index_in_current_keys(&kc)?;
                    let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                    id.finalize_group_event(
                        &multisig_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await?;
                }
                ActionRequired::DelegationRequest(delegating_event, exn) => {
                    let signature_ixn = SelfSigningPrefix::Ed25519Sha512(
                        keypair.sign(&delegating_event.encode()?)?,
                    );
                    let signature_exn =
                        SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn.encode()?)?);
                    let kc = id.find_state(id.id()).unwrap().current;
                    let index = id.index_in_current_keys(&kc)?;
                    let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                    id.finalize_group_event(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![(exn.encode()?, exn_index_signature)],
                    )
                    .await
                    .unwrap();
                    id.notify_witnesses().await?;

                    // Query for receipts
                    let query = id.query_mailbox(&delegator_group_id, witness_id)?;

                    for qry in query {
                        let signature =
                            SelfSigningPrefix::Ed25519Sha512(keypair.sign(&qry.encode()?)?);
                        let _action_required =
                            id.finalize_query_mailbox(vec![(qry, signature)]).await?;
                        // assert!(action_required.is_empty());
                    }

                    let kc = id.find_state(&delegator_group_id).unwrap().current;
                    let index = id.index_in_current_keys(&kc).unwrap();
                    // send accepted event to child
                    let exn_message = Exchange::Fwd {
                        args: FwdArgs {
                            recipient_id: delegatee_id.clone(),
                            topic: ForwardTopic::Delegate,
                        },
                        to_forward: delegating_event.clone(),
                    }
                    .to_message(SerializationFormats::JSON, HashFunctionCode::Blake3_256);
                    let signature_exn =
                        SelfSigningPrefix::Ed25519Sha512(keypair.sign(&exn_message.encode()?)?);

                    let data_signature =
                        IndexedSignature::new_both_same(signature_ixn, index as u16);

                    let kc = id.find_state(&id.id()).unwrap().current;
                    let index = id.index_in_current_keys(&kc).unwrap();
                    let exn_index_signature = id.sign_with_index(signature_exn, index as u16)?;
                    id.finalize_exchange(
                        &exn_message.encode()?,
                        exn_index_signature,
                        data_signature,
                    )
                    .await?;
                }
            };
        }
    }
    Ok(())
}
