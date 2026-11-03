//! A group view: an `Identifier` whose id is a group, held by a controller
//! that holds one of the group's member keys but not necessarily the first.
//! A second device that joined a group signs this way.

use std::sync::{Arc, Mutex};

use keri_controller::{
    config::ControllerConfig,
    controller::{Controller, RedbController, RedbIdentifier},
    error::ControllerError,
    identifier::Identifier,
    IdentifierPrefix,
};
use keri_core::{
    actor::prelude::HashFunctionCode,
    prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
};
use said::{derivation::HashFunction, SelfAddressingIdentifier};
use tempfile::{Builder, TempDir};

/// Queries sent, as they left the controller.
type Sent = Arc<Mutex<Vec<keri_core::query::query_event::SignedQueryMessage>>>;

struct Fixture {
    _root: TempDir,
    sent: Sent,
    controller: Arc<RedbController>,
    group: IdentifierPrefix,
    /// The keys of the group's first member (index 0).
    first: CryptoBox,
    /// The keys of the group's second member (index 1).
    second: CryptoBox,
}

/// A two-member group either member may sign alone (threshold 1).
async fn setup() -> Result<Fixture, ControllerError> {
    let root = Builder::new().prefix("test-group-view").tempdir().unwrap();
    let sent = Sent::default();
    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(Recording(sent.clone())),
        ..Default::default()
    })?);

    let first = CryptoBox::new()?;
    let second = CryptoBox::new()?;
    let incept = |km: &CryptoBox| {
        let controller = controller.clone();
        let pk = BasicPrefix::Ed25519(km.public_key());
        let npk = BasicPrefix::Ed25519(km.next_public_key());
        async move { controller.incept(vec![pk], vec![npk], vec![], 0).await }
    };

    let icp = incept(&first).await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(first.sign(icp.as_bytes())?);
    let mut member1 = controller.finalize_incept(icp.as_bytes(), &sig)?;
    let icp = incept(&second).await?;
    let sig = SelfSigningPrefix::Ed25519Sha512(second.sign(icp.as_bytes())?);
    let member2 = controller.finalize_incept(icp.as_bytes(), &sig)?;

    let (group_icp, exns) =
        member1.incept_group(vec![member2.id().clone()], 1, Some(1), None, None, None)?;
    let sig_icp = SelfSigningPrefix::Ed25519Sha512(first.sign(group_icp.as_bytes())?);
    let sig_exn = SelfSigningPrefix::Ed25519Sha512(first.sign(exns[0].as_bytes())?);
    let exn_sig = member1.sign_with_index(sig_exn, 0)?;
    let (group, _forwards) = member1
        .finalize_group_incept(
            group_icp.as_bytes(),
            sig_icp,
            vec![(exns[0].as_bytes().to_vec(), exn_sig)],
        )
        .await?;

    let state = controller.find_state(&group)?;
    assert_eq!(state.sn, 0, "the group is incepted on the first signature");
    assert_eq!(
        state.current.public_keys[1],
        BasicPrefix::Ed25519(second.public_key()),
        "the second member holds slot 1"
    );

    Ok(Fixture {
        _root: root,
        sent,
        controller,
        group,
        first,
        second,
    })
}

fn view(fx: &Fixture) -> RedbIdentifier {
    Identifier::new(
        fx.group.clone(),
        fx.controller.known_events.clone(),
        fx.controller.communication.clone(),
        fx.controller.cache.clone(),
    )
}

fn digest(data: &str) -> SelfAddressingIdentifier {
    HashFunction::from(HashFunctionCode::Blake3_256).derive(data.as_bytes())
}

/// The indexes of the signatures of the group's event at `sn`, in order.
fn signature_indexes(fx: &Fixture, sn: u64) -> Vec<u16> {
    use keri_core::event_message::signed_event_message::Notice;
    fx.controller
        .get_kel_with_receipts(&fx.group)
        .unwrap()
        .into_iter()
        .find_map(|notice| match notice {
            Notice::Event(ev) if ev.event_message.data.get_sn() == sn => {
                let mut indexes: Vec<u16> =
                    ev.signatures.iter().map(|s| s.index.current()).collect();
                indexes.sort();
                Some(indexes)
            }
            _ => None,
        })
        .unwrap_or_else(|| panic!("the group has an accepted event at sn {sn}"))
}

#[async_std::test]
async fn an_anchor_signed_by_the_second_member_alone_is_accepted_and_sent(
) -> Result<(), ControllerError> {
    let fx = setup().await?;
    let mut view = view(&fx);

    let ixn = view.anchor(&[digest("payload")])?;
    let sig = SelfSigningPrefix::Ed25519Sha512(fx.second.sign(ixn.as_bytes())?);
    view.finalize_anchor(ixn.as_bytes(), sig).await?;

    assert_eq!(fx.controller.find_state(&fx.group)?.sn, 1);
    assert_eq!(signature_indexes(&fx, 1), vec![1]);
    assert_eq!(
        view.notify_witnesses().await?,
        1,
        "the only signer of the event is the one to send it"
    );
    Ok(())
}

#[async_std::test]
async fn a_registry_issued_by_the_second_member_alone_is_anchored() -> Result<(), ControllerError> {
    let fx = setup().await?;
    let mut view = view(&fx);

    let rip = view.incept_registry()?;
    let acdc = digest("credential");
    let (pending, ixn) =
        view.issue_in(rip, &keri_controller::registry::Blinding::private(), &acdc)?;
    let ixn = ixn.encode()?;
    let sig = SelfSigningPrefix::Ed25519Sha512(fx.second.sign(&ixn)?);
    view.finalize_registry_events(&pending, &ixn, sig).await?;

    assert_eq!(fx.controller.find_state(&fx.group)?.sn, 1);
    assert_eq!(signature_indexes(&fx, 1), vec![1]);
    assert_eq!(view.notify_witnesses().await?, 1);
    Ok(())
}

/// A view that knows its key leaves an event the first member signed too
/// to the first member: the signer of the lowest index sends it. The key
/// may be given in either encoding.
#[async_std::test]
async fn a_view_told_its_key_leaves_a_jointly_signed_event_to_the_first_member(
) -> Result<(), ControllerError> {
    let fx = setup().await?;
    let mut view = view(&fx);
    view.set_own_key(BasicPrefix::Ed25519NT(fx.second.public_key()));

    let ixn = view.anchor(&[digest("payload")])?;
    let signed = |km: &CryptoBox, index| {
        let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(ixn.as_bytes()).unwrap());
        IndexedSignature::new_both_same(sig, index)
    };
    let signatures = vec![signed(&fx.first, 0), signed(&fx.second, 1)];
    view.finalize_anchor_multi(ixn.as_bytes(), signatures)
        .await?;

    assert_eq!(signature_indexes(&fx, 1), vec![0, 1]);
    assert_eq!(view.notify_witnesses().await?, 0);
    Ok(())
}

/// Without being told its key, a view whose group has several keys cannot
/// tell whether it signs first, so it sends what it signed rather than
/// leave it unsent.
#[async_std::test]
async fn a_view_not_told_its_key_sends_an_event_it_signed_with_others(
) -> Result<(), ControllerError> {
    let fx = setup().await?;
    let mut view = view(&fx);

    let ixn = view.anchor(&[digest("payload")])?;
    let sig = SelfSigningPrefix::Ed25519Sha512(fx.second.sign(ixn.as_bytes())?);
    view.finalize_anchor_multi(
        ixn.as_bytes(),
        vec![IndexedSignature::new_both_same(sig, 1)],
    )
    .await?;

    assert_eq!(view.notify_witnesses().await?, 1);
    Ok(())
}

/// A transport that keeps every query it is handed and answers it with an
/// empty log; nothing else is sent in these tests.
struct Recording(Sent);

#[async_trait::async_trait]
impl keri_core::transport::Transport for Recording {
    async fn send_message(
        &self,
        _loc: keri_controller::LocationScheme,
        _msg: keri_core::event_message::signed_event_message::Message,
    ) -> Result<(), keri_core::transport::TransportError> {
        Ok(())
    }

    async fn send_query(
        &self,
        _loc: keri_controller::LocationScheme,
        qry: keri_core::query::query_event::SignedQueryMessage,
    ) -> Result<
        keri_core::actor::possible_response::PossibleResponse,
        keri_core::transport::TransportError,
    > {
        self.0.lock().unwrap().push(qry);
        Ok(keri_core::actor::possible_response::PossibleResponse::Kel(
            vec![],
        ))
    }

    async fn request_loc_scheme(
        &self,
        _loc: keri_controller::LocationScheme,
    ) -> Result<
        Vec<keri_core::event_message::signed_event_message::Op>,
        keri_core::transport::TransportError,
    > {
        Ok(vec![])
    }

    async fn request_end_role(
        &self,
        _loc: keri_controller::LocationScheme,
        _cid: IdentifierPrefix,
        _role: keri_core::oobi::Role,
        _eid: IdentifierPrefix,
    ) -> Result<Vec<u8>, keri_core::transport::TransportError> {
        Ok(vec![])
    }

    async fn resolve_oobi(
        &self,
        _loc: keri_controller::LocationScheme,
        _oobi: keri_controller::Oobi,
    ) -> Result<(), keri_core::transport::TransportError> {
        Ok(())
    }
}

/// A watcher whose location the controller knows.
fn known_watcher(fx: &Fixture) -> IdentifierPrefix {
    use keri_core::{
        actor::prelude::SerializationFormats,
        event_message::keri_version::KeriVersion,
        oobi::Scheme,
        query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        signer::Signer,
    };
    let signer = Signer::new();
    let key = BasicPrefix::Ed25519NT(signer.public_key());
    let id = IdentifierPrefix::Basic(key.clone());
    let reply = ReplyEvent::new_reply(
        ReplyRoute::LocScheme(keri_controller::LocationScheme::new(
            id.clone(),
            Scheme::Http,
            "http://watcher-under-test/".parse().unwrap(),
        )),
        &id,
        KeriVersion::V1_0,
        HashFunctionCode::Blake3_256,
        SerializationFormats::JSON,
    );
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(reply.encode().unwrap()).unwrap());
    fx.controller
        .known_events
        .save_oobi(&SignedReply::new_nontrans(reply, key, sig))
        .unwrap();
    id
}

/// A query the second member signs alone is sent with its signature at
/// the second member's index, so the watcher can verify it.
#[async_std::test]
async fn a_query_signed_by_the_second_member_names_its_index() -> Result<(), ControllerError> {
    use keri_core::query::query_event::SignedQueryMessage;

    let fx = setup().await?;
    let view = view(&fx);
    let watcher = known_watcher(&fx);

    let qry = view.query_full_log(&fx.group, watcher)?;
    let sig = SelfSigningPrefix::Ed25519Sha512(fx.second.sign(&qry.encode()?)?);
    let (_, errors) = view.finalize_query(vec![(qry.clone(), sig)]).await;
    assert!(errors.is_empty(), "{errors:?}");

    let sent = fx.sent.lock().unwrap();
    let [SignedQueryMessage::KelQuery(signed)] = sent.as_slice() else {
        panic!("one log query sent: {sent:?}");
    };
    let keri_core::event_message::signature::Signature::Transferable(_, sigs) = &signed.signature
    else {
        panic!("a group signs transferably: {:?}", signed.signature);
    };
    assert_eq!(
        sigs.iter().map(|s| s.index.current()).collect::<Vec<_>>(),
        vec![1]
    );
    fx.controller
        .verify(&qry.encode()?, &signed.signature)
        .expect("the query verifies against the group's key state");
    Ok(())
}
