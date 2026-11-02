//! The delegated inception both storage backends must pass. Witnesses only
//! witness: each side collects its receipts by asking the witness for the
//! KEL, and the delegation request and its approval travel as forwards the
//! test delivers itself, as an application would through a messagebox.

use keri_controller::{
    controller::Controller, error::ControllerError, identifier::Identifier,
    ActionRequired, LocationScheme,
};
use keri_core::{
    database::{EscrowCreator, EventDatabase},
    event_message::signed_event_message::Message,
    oobi_manager::storage::OobiStorageBackend,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use teliox::registry::RegistryStore;

/// Collects `about`'s receipts from `witness`, signing with `keys`.
async fn receipts<D, T, S>(
    identifier: &mut Identifier<D, T, S>,
    keys: &CryptoBox,
    about: &IdentifierPrefix,
    witness: &BasicPrefix,
) -> Result<(), ControllerError>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    let queries = identifier
        .query_receipts(about, std::slice::from_ref(witness))?
        .into_iter()
        .map(|qry| {
            let signature = SelfSigningPrefix::Ed25519Sha512(keys.sign(&qry.encode()?)?);
            Ok((qry, signature))
        })
        .collect::<Result<Vec<_>, ControllerError>>()?;
    identifier.finalize_query_receipts(queries).await?;
    Ok(())
}

async fn incept<D, T, S>(
    controller: &Controller<D, T, S>,
    keys: &CryptoBox,
    witness: &LocationScheme,
) -> Result<Identifier<D, T, S>, ControllerError>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(keys.public_key())],
            vec![BasicPrefix::Ed25519(keys.next_public_key())],
            vec![witness.clone()],
            1,
        )
        .await?;
    let signature = SelfSigningPrefix::Ed25519Sha512(keys.sign(icp.as_bytes())?);
    let mut identifier = controller.finalize_incept(icp.as_bytes(), &signature)?;
    identifier.notify_witnesses().await?;
    Ok(identifier)
}

/// A delegatee requests a delegated inception; the delegator approves it;
/// the delegated identifier is accepted once witnessed.
pub async fn delegated_inception<D, T, S>(
    delegatee_controller: &Controller<D, T, S>,
    delegator_controller: &Controller<D, T, S>,
    witness: &LocationScheme,
) -> Result<(), ControllerError>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    let IdentifierPrefix::Basic(witness_id) = witness.eid.clone() else {
        panic!("a witness has a basic prefix")
    };
    let delegatee_keys = CryptoBox::new()?;
    let mut delegatee = incept(delegatee_controller, &delegatee_keys, witness).await?;
    let delegatee_id = delegatee.id().clone();
    receipts(&mut delegatee, &delegatee_keys, &delegatee_id, &witness_id).await?;

    let delegator_keys = CryptoBox::new()?;
    let mut delegator = incept(delegator_controller, &delegator_keys, witness).await?;
    let delegator_id = delegator.id().clone();
    receipts(&mut delegator, &delegator_keys, &delegator_id, &witness_id).await?;

    // Each side knows the other's KEL, as contacts.
    for notice in delegatee_controller.get_kel_with_receipts(&delegatee_id).unwrap() {
        delegator_controller.known_events.save(&Message::Notice(notice))?;
    }
    for notice in delegator_controller.get_kel_with_receipts(&delegator_id).unwrap() {
        delegatee_controller.known_events.save(&Message::Notice(notice))?;
    }

    // The delegatee requests a delegated inception.
    let (delegated_inception, exn_messages) = delegatee.incept_group(
        vec![],
        1,
        Some(1),
        Some(vec![witness_id.clone()]),
        Some(1),
        Some(delegator_id.clone()),
    )?;
    let signature_icp =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keys.sign(delegated_inception.as_bytes())?);
    let signature_exn =
        SelfSigningPrefix::Ed25519Sha512(delegatee_keys.sign(exn_messages[0].as_bytes())?);
    let exn_index_signature = delegatee.sign_with_index(signature_exn, 0)?;
    let (delegate_id, forwards) = delegatee
        .finalize_group_incept(
            delegated_inception.as_bytes(),
            signature_icp,
            vec![(exn_messages[0].as_bytes().to_vec(), exn_index_signature)],
        )
        .await?;
    // Not accepted yet: the delegating event is missing.
    assert!(delegatee_controller.get_kel_with_receipts(&delegate_id).is_none());
    let [request] = forwards.as_slice() else {
        panic!("one forward, to the delegator: {forwards:?}")
    };
    assert_eq!(request.to, delegator_id);

    // The delegator receives the request and approves it.
    let actions = delegator.receive_forwards(&request.message).await?;
    let [ActionRequired::DelegationRequest(delegating_event, exn)] = actions.as_slice() else {
        panic!("one delegation request: {actions:?}")
    };
    let signature_ixn =
        SelfSigningPrefix::Ed25519Sha512(delegator_keys.sign(&delegating_event.encode()?)?);
    let signature_exn = SelfSigningPrefix::Ed25519Sha512(delegator_keys.sign(&exn.encode()?)?);
    let exn_index_signature = delegator.sign_with_index(signature_exn, 0)?;
    delegator
        .finalize_group_event(&delegating_event.encode()?, signature_ixn.clone(), vec![])
        .await?;
    delegator.notify_witnesses().await?;
    receipts(&mut delegator, &delegator_keys, &delegator_id, &witness_id).await?;
    assert_eq!(delegator_controller.find_state(&delegator_id)?.sn, 1);
    let approval = delegator.finalize_exchange(
        &exn.encode()?,
        exn_index_signature,
        delegating_event,
        IndexedSignature::new_both_same(signature_ixn, 0),
    )?;
    assert_eq!(approval.to, delegate_id);

    // The delegatee receives the approval: the delegating event, which lets
    // the delegated inception go to the witness.
    let actions = delegatee.receive_forwards(&approval.message).await?;
    assert!(actions.is_empty(), "{actions:?}");
    assert_eq!(delegatee.find_state(&delegator_id)?.sn, 1);
    assert!(delegatee.find_state(&delegate_id).is_err());

    // Once the witness receipts it, the delegated identifier is accepted.
    receipts(&mut delegatee, &delegatee_keys, &delegate_id, &witness_id).await?;
    assert_eq!(delegatee.find_state(&delegate_id)?.sn, 0);
    Ok(())
}
