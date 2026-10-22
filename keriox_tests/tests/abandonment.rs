//! An identifier abandoned with a rotation to no next keys (`n=[]`, `nt=0`)
//! stays final everywhere: its witnesses refuse anything after it, and a
//! verifier that never saw it before learns it is abandoned through a
//! watcher.

use std::{sync::Arc, time::Duration};

use actix_rt::time::sleep;
use keri_controller::{
    config::ControllerConfig, error::ControllerError, identifier::mechanics::MechanicsError,
    mailbox_updating::ActionRequired, BasicPrefix, CryptoBox, EndRole, IdentifierPrefix,
    KeyManager, LocationScheme, Oobi, RedbController, RedbIdentifier, SelfSigningPrefix,
};
use keri_core::{
    actor::{error::ActorError, prelude::Message},
    error::Error,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::IndexedSignature,
    transport::{default::DefaultTransport, Transport, TransportError},
};
use keri_tests::settings::InfrastructureContext;
use said::SelfAddressingIdentifier;
use tempfile::{Builder, TempDir};
use test_context::test_context;

/// A controller of its own, in a fresh database.
fn controller() -> Result<(TempDir, Arc<RedbController>), ControllerError> {
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Arc::new(RedbController::new(ControllerConfig {
        db_path: root.path().to_owned(),
        ..Default::default()
    })?);
    Ok((root, controller))
}

fn sign(km: &CryptoBox, data: &[u8]) -> SelfSigningPrefix {
    SelfSigningPrefix::Ed25519Sha512(km.sign(data).unwrap())
}

async fn collect_receipts(
    id: &mut RedbIdentifier,
    km: &CryptoBox,
    about: &IdentifierPrefix,
    witnesses: &[BasicPrefix],
) -> Result<Vec<ActionRequired>, ControllerError> {
    let mut actions = vec![];
    for qry in id.query_mailbox(about, witnesses)? {
        let signature = sign(km, &qry.encode()?);
        actions.extend(id.finalize_query_mailbox(vec![(qry, signature)]).await?);
    }
    Ok(actions)
}

/// Incept an identifier with `km`'s keys, witnessed by `witnesses` with
/// threshold `threshold`, and collect its receipts.
async fn incept(
    controller: &RedbController,
    km: &CryptoBox,
    witnesses: &[LocationScheme],
    threshold: u64,
) -> Result<RedbIdentifier, ControllerError> {
    let icp = controller
        .incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            witnesses.to_vec(),
            threshold,
        )
        .await?;
    let mut id = controller.finalize_incept(icp.as_bytes(), &sign(km, icp.as_bytes()))?;
    id.notify_witnesses().await?;
    let own = id.id().clone();
    collect_receipts(&mut id, km, &own, &witness_ids(witnesses)).await?;
    Ok(id)
}

fn witness_ids(witnesses: &[LocationScheme]) -> Vec<BasicPrefix> {
    witnesses
        .iter()
        .map(|loc| match &loc.eid {
            IdentifierPrefix::Basic(bp) => bp.clone(),
            _ => unreachable!(),
        })
        .collect()
}

/// Abandon `id` by revealing `km`'s next key, and collect the receipts.
async fn abandon(
    id: &mut RedbIdentifier,
    km: &mut CryptoBox,
    witness_threshold: u64,
    witnesses: &[BasicPrefix],
) -> Result<(), ControllerError> {
    km.rotate()?;
    let event = id
        .abandon(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![],
            vec![],
            witness_threshold,
            vec![],
        )
        .await?;
    id.finalize_rotate(event.as_bytes(), sign(km, event.as_bytes()))
        .await?;
    id.notify_witnesses().await?;
    let own = id.id().clone();
    collect_receipts(id, km, &own, witnesses).await?;
    Ok(())
}

fn signed_by(event: &KeriEvent<KeyEvent>, km: &CryptoBox) -> Notice {
    let signature = sign(km, &event.encode().unwrap());
    Notice::Event(event.sign(
        vec![IndexedSignature::new_both_same(signature, 0)],
        None,
        None,
    ))
}

fn is_refused_as_abandoned(result: Result<(), TransportError<ActorError>>) -> bool {
    matches!(
        result,
        Err(TransportError::RemoteError(ActorError::KeriError(
            Error::AbandonedIdentifier(_)
        )))
    )
}

async fn public_state(base: &LocationScheme, id: &IdentifierPrefix) -> serde_json::Value {
    let url = base.url.join(&format!("identifiers/{id}/state")).unwrap();
    let body = reqwest::get(url).await.unwrap().text().await.unwrap();
    serde_json::from_str(&body).unwrap()
}

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn an_abandoned_identifier_is_final_for_witnesses_and_watchers(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (first_witness_id, first_witness) = ctx.first_witness_data();
    let (second_witness_id, second_witness) = ctx.second_witness_data();
    let witnesses = vec![first_witness.clone(), second_witness.clone()];
    let witness_ids = vec![first_witness_id.clone(), second_witness_id.clone()];

    // The identifier to abandon, receipted by both witnesses.
    let (_a_root, a_controller) = controller()?;
    let mut a_km = CryptoBox::new()?;
    let mut a = incept(&a_controller, &a_km, &witnesses, 2).await?;
    abandon(&mut a, &mut a_km, 2, &witness_ids).await?;

    assert!(a.is_abandoned());
    let abandonment = a.find_state(a.id())?;
    assert_eq!(abandonment.sn, 1);
    let abandonment_said: SelfAddressingIdentifier = abandonment.last_event_digest.said.clone();

    // Nothing after the abandonment is receipted: not a rotation to an
    // attacker's keys, nor an interaction signed by the last keys.
    let attacker = CryptoBox::new()?;
    let takeover = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(a.id())
        .with_sn(2)
        .with_previous_event(&abandonment_said)
        .with_keys(vec![BasicPrefix::Ed25519(attacker.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(attacker.next_public_key())])
        .with_next_threshold(&SignatureThreshold::Simple(1))
        .build()
        .unwrap();
    let interaction = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(a.id())
        .with_sn(2)
        .with_previous_event(&abandonment_said)
        .build()
        .unwrap();
    let transport = DefaultTransport::<ActorError>::new();
    for witness in &witnesses {
        for forged in [
            signed_by(&takeover, &attacker),
            signed_by(&interaction, &a_km),
        ] {
            assert!(is_refused_as_abandoned(
                transport
                    .send_message(witness.clone(), Message::Notice(forged))
                    .await
            ));
        }
    }

    // The controller reports the refusal instead of swallowing it.
    if let Notice::Event(event) = signed_by(&interaction, &a_km) {
        a.to_notify.push(event);
    }
    assert!(matches!(
        a.notify_witnesses().await,
        Err(MechanicsError::IdentifierAbandoned(id)) if &id == a.id()
    ));

    // A verifier that has never seen the identifier asks its watcher.
    let (_b_root, b_controller) = controller()?;
    let b_km = CryptoBox::new()?;
    let mut b = incept(&b_controller, &b_km, &[first_witness.clone()], 1).await?;
    let (watcher_id, watcher) = ctx.watcher_data();
    b.resolve_oobi(&Oobi::Location(watcher.clone())).await?;
    let add_watcher = b.add_watcher(IdentifierPrefix::Basic(watcher_id))?;
    b.finalize_add_watcher(add_watcher.as_bytes(), sign(&b_km, add_watcher.as_bytes()))
        .await?;
    for witness in &witnesses {
        let oobi = Oobi::Location(witness.clone());
        b.resolve_oobi(&oobi).await?;
        b.send_oobi_to_watcher(b.id(), &oobi).await?;
    }
    let a_witness = EndRole {
        cid: a.id().clone(),
        role: keri_core::oobi::Role::Witness,
        eid: IdentifierPrefix::Basic(second_witness_id.clone()),
    };
    b.send_oobi_to_watcher(b.id(), &Oobi::EndRole(a_witness))
        .await?;

    let queries: Vec<_> = b
        .query_watchers(&a.get_last_event_seal()?)?
        .into_iter()
        .map(|qry| {
            let signature = sign(&b_km, &qry.encode().unwrap());
            (qry, signature)
        })
        .collect();
    let (_, mut errors) = b.finalize_query(queries.clone()).await;
    while !errors.is_empty() {
        sleep(Duration::from_millis(500)).await;
        (_, errors) = b.finalize_query(queries.clone()).await;
    }

    let seen = b.find_state(a.id())?;
    assert!(seen.is_abandoned());
    assert_eq!(seen.sn, 1);
    assert_eq!(seen.last_event_digest.said, abandonment_said);

    // Witnesses and the watcher report it publicly too.
    for endpoint in [&first_witness, &second_witness, &watcher] {
        let state = public_state(endpoint, a.id()).await;
        assert_eq!(state["abandoned"]["sn"], 1, "{}", endpoint.url);
        assert_eq!(
            state["abandoned"]["said"],
            abandonment_said.to_string(),
            "{}",
            endpoint.url
        );
    }

    Ok(())
}

/// The delegator approves every delegation request waiting in its mailbox.
async fn approve_delegations(
    delegator: &mut RedbIdentifier,
    km: &CryptoBox,
    witnesses: &[BasicPrefix],
) -> Result<(), ControllerError> {
    let own = delegator.id().clone();
    for action in collect_receipts(delegator, km, &own, witnesses).await? {
        match action {
            ActionRequired::DelegationRequest(delegating_event, exn) => {
                let signature_ixn = sign(km, &delegating_event.encode()?);
                let signature_exn = sign(km, &exn.encode()?);
                delegator
                    .finalize_group_event(
                        &delegating_event.encode()?,
                        signature_ixn.clone(),
                        vec![],
                    )
                    .await?;
                delegator.notify_witnesses().await?;
                collect_receipts(delegator, km, &own, witnesses).await?;
                let exn_signature = delegator.sign_with_index(signature_exn, 0)?;
                delegator
                    .finalize_exchange(
                        &exn.encode()?,
                        exn_signature,
                        IndexedSignature::new_both_same(signature_ixn, 0),
                    )
                    .await?;
            }
            ActionRequired::MultisigRequest(_, _) => unreachable!(),
        }
    }
    Ok(())
}

/// Hand the delegator's KEL to the delegate's controller, so it can check
/// the delegator's anchors.
fn share_kel(
    from: &RedbController,
    to: &RedbController,
    id: &IdentifierPrefix,
) -> Result<(), ControllerError> {
    for notice in from.get_kel_with_receipts(id).unwrap() {
        to.known_events.save(&Message::Notice(notice))?;
    }
    Ok(())
}

#[test_context(InfrastructureContext)]
#[actix_rt::test]
async fn a_delegated_identifier_is_abandoned_with_its_delegators_approval(
    ctx: &mut InfrastructureContext,
) -> Result<(), ControllerError> {
    let (witness_id, witness) = ctx.first_witness_data();
    let witness_ids = vec![witness_id.clone()];

    let (_delegator_root, delegator_controller) = controller()?;
    let mut delegator_km = CryptoBox::new()?;
    let mut delegator = incept(&delegator_controller, &delegator_km, &[witness.clone()], 1).await?;

    // The delegate's own identifier, through which it acts for the
    // delegated one.
    let (_delegate_root, delegate_controller) = controller()?;
    let mut member_km = CryptoBox::new()?;
    let mut member = incept(&delegate_controller, &member_km, &[witness.clone()], 1).await?;

    let (dip, exchanges) = member.incept_group(
        vec![],
        1,
        Some(1),
        Some(witness_ids.clone()),
        Some(1),
        Some(delegator.id().clone()),
    )?;
    let exn_signature = member.sign_with_index(sign(&member_km, exchanges[0].as_bytes()), 0)?;
    let delegated = member
        .finalize_group_incept(
            dip.as_bytes(),
            sign(&member_km, dip.as_bytes()),
            vec![(exchanges[0].as_bytes().to_vec(), exn_signature)],
        )
        .await?;

    approve_delegations(&mut delegator, &delegator_km, &witness_ids).await?;
    share_kel(&delegator_controller, &delegate_controller, delegator.id())?;
    collect_receipts(&mut member, &member_km, &delegated, &witness_ids).await?;
    collect_receipts(&mut member, &member_km, &delegated, &witness_ids).await?;
    assert_eq!(member.find_state(&delegated)?.sn, 0);

    // The member reveals the key the delegated identifier committed to by
    // rotating its own identifier, then signs the abandoning `drt`.
    member_km.rotate()?;
    let rotation = member
        .rotate(
            vec![BasicPrefix::Ed25519(member_km.public_key())],
            vec![BasicPrefix::Ed25519(member_km.next_public_key())],
            1,
            vec![],
            vec![],
            1,
        )
        .await?;
    member
        .finalize_rotate(rotation.as_bytes(), sign(&member_km, rotation.as_bytes()))
        .await?;
    member.notify_witnesses().await?;
    let own = member.id().clone();
    collect_receipts(&mut member, &member_km, &own, &witness_ids).await?;

    let (drt, exchanges) = member
        .abandon_group(&delegated, vec![member.id().clone()], 1, vec![])
        .await?;
    assert!(drt.contains(r#""t":"drt""#));
    // Only the delegation request: there are no other members.
    assert_eq!(exchanges.len(), 1);
    let exn_signature = member.sign_with_index(sign(&member_km, exchanges[0].as_bytes()), 0)?;
    member
        .finalize_group_event(
            drt.as_bytes(),
            sign(&member_km, drt.as_bytes()),
            vec![(exchanges[0].as_bytes().to_vec(), exn_signature)],
        )
        .await?;

    approve_delegations(&mut delegator, &delegator_km, &witness_ids).await?;
    share_kel(&delegator_controller, &delegate_controller, delegator.id())?;
    collect_receipts(&mut member, &member_km, &delegated, &witness_ids).await?;
    collect_receipts(&mut member, &member_km, &delegated, &witness_ids).await?;

    let state = member.find_state(&delegated)?;
    assert_eq!(state.sn, 1);
    assert!(state.is_abandoned());
    let witnessed = public_state(&witness, &delegated).await;
    assert_eq!(witnessed["abandoned"]["sn"], 1);

    // With its delegates gone, the delegator abandons itself.
    abandon(&mut delegator, &mut delegator_km, 1, &witness_ids).await?;
    assert!(delegator.is_abandoned());
    assert_eq!(
        public_state(&witness, delegator.id()).await["abandoned"]["sn"],
        delegator.find_state(delegator.id())?.sn
    );

    Ok(())
}
