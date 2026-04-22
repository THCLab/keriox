//! Witness notification should surface transport failures from `publish`.
//!
//! See `publish_bug.md`: today `Communication::publish` and
//! `Identifier::notify_witnesses` drop `send_message` errors and clear
//! `to_notify`. The test below asserts the **correct** contract: it **fails**
//! on the current codebase and should pass once those errors propagate and the
//! queue is only cleared after success.

use std::{collections::HashMap, sync::Arc};

use keri_controller::{config::ControllerConfig, controller::Controller, error::ControllerError};
use keri_core::{
    actor::{error::ActorError, possible_response::PossibleResponse},
    event_message::signed_event_message::{Message, Op},
    oobi::{LocationScheme, Oobi, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::query_event::SignedQueryMessage,
    signer::{CryptoBox, KeyManager},
    transport::test::{TestActor, TestTransport},
};
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

/// [`TestActor`] that performs real OOBI resolution like [`WitnessListener`] but
/// always fails witness-bound `send_message` (the path used by `publish`).
struct FailingSendWitness<S: keri_core::oobi_manager::storage::OobiStorageBackend> {
    inner: Arc<WitnessListener<S>>,
}

#[async_trait::async_trait]
impl<S> TestActor for FailingSendWitness<S>
where
    S: keri_core::oobi_manager::storage::OobiStorageBackend + Send + Sync + 'static,
{
    async fn send_message(&self, _msg: Message) -> Result<(), ActorError> {
        Err(ActorError::DbError(
            "simulated witness transport failure (publish path)".into(),
        ))
    }

    async fn send_query(&self, query: SignedQueryMessage) -> Result<PossibleResponse, ActorError> {
        TestActor::send_query(self.inner.as_ref(), query).await
    }

    async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError> {
        TestActor::request_loc_scheme(self.inner.as_ref(), eid).await
    }

    async fn request_end_role(
        &self,
        cid: IdentifierPrefix,
        role: Role,
        eid: IdentifierPrefix,
    ) -> Result<Vec<u8>, ActorError> {
        TestActor::request_end_role(self.inner.as_ref(), cid, role, eid).await
    }

    async fn resolve_oobi(&self, msg: Oobi) -> Result<(), ActorError> {
        TestActor::resolve_oobi(self.inner.as_ref(), msg).await
    }
}

#[async_std::test]
async fn notify_witnesses_propagates_errors_and_keeps_queue_when_publish_fails() -> Result<(), ControllerError> {
    let root = Builder::new().prefix("notify-wit-bug-db").tempdir().unwrap();

    let witness = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("notify-wit-bug-wit-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup_with_redb(
                url::Url::parse("http://witness1/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let wit_id = witness.get_prefix();
    let wit_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit_id.clone()),
        scheme: Scheme::Http,
        url: url::Url::parse("http://witness1/").unwrap(),
    };

    let transport = {
        let mut actors: keri_core::transport::test::TestActorMap = HashMap::new();
        actors.insert(
            (Host::Domain("witness1".to_string()), 80),
            Arc::new(FailingSendWitness {
                inner: witness.clone(),
            }),
        );
        TestTransport::new(actors)
    };

    let controller = Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(transport),
        ..Default::default()
    })?;

    let km = CryptoBox::new()?;
    let pk = BasicPrefix::Ed25519(km.public_key());
    let npk = BasicPrefix::Ed25519(km.next_public_key());

    let icp_event = controller
        .incept(
            vec![pk],
            vec![npk],
            vec![wit_location.clone()],
            1,
        )
        .await?;

    let signature = SelfSigningPrefix::Ed25519Sha512(km.sign(icp_event.as_bytes())?);
    let mut identifier = controller.finalize_incept(icp_event.as_bytes(), &signature)?;

    assert!(
        !identifier.to_notify.is_empty(),
        "fixture should leave at least one partially witnessed event to publish"
    );

    let outcome = identifier.notify_witnesses().await;
    assert!(
        outcome.is_err(),
        "notify_witnesses must return Err when witness send_message fails (got {outcome:?})"
    );

    assert!(
        !identifier.to_notify.is_empty(),
        "to_notify must be retained when publish fails so the caller can retry (got empty queue)"
    );

    let kel = witness
        .witness_data
        .event_storage
        .get_kel_messages_with_receipts_all(&identifier.id())?;
    assert!(
        kel.unwrap_or_default().is_empty(),
        "witness should not have accepted the event when send always fails"
    );

    Ok(())
}
