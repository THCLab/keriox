use std::sync::{Arc, Mutex};

use keri::{
    actor::{
        parse_event_stream,
        simple_controller::{PossibleResponse, SimpleController},
    },
    database::{escrow::EscrowDb, SledEventDatabase},
    derivation::self_signing::SelfSigning,
    error::Error,
    event_message::signed_event_message::{Message, Notice, Op},
    oobi::{LocationScheme, Role},
    prefix::IdentifierPrefix,
    query::reply_event::SignedReply,
};
use keri_transport::{Transport, TransportError};
use tempfile::Builder;
use watcher::{WatcherData, WatcherError};
use witness::Witness;

struct FakeTransport {
    send_message:
        Box<dyn Fn(LocationScheme, Message) -> Result<Vec<Message>, TransportError> + Send + Sync>,
}

#[async_trait::async_trait]
impl Transport for FakeTransport {
    async fn send_message(
        &self,
        loc: LocationScheme,
        msg: Message,
    ) -> Result<Vec<Message>, TransportError> {
        (self.send_message)(loc, msg)
    }

    async fn request_loc_scheme(&self, _loc: LocationScheme) -> Result<Vec<Op>, TransportError> {
        todo!()
    }

    async fn request_end_role(
        &self,
        _loc: LocationScheme,
        _cid: IdentifierPrefix,
        _role: Role,
        _eid: IdentifierPrefix,
    ) -> Result<Vec<Op>, TransportError> {
        todo!()
    }
}

#[test]
pub fn watcher_forward_ksn() -> Result<(), Error> {
    let witness_url = url::Url::parse("http://some/witness/url").unwrap();

    let witness = Arc::new({
        let root_witness = Builder::new().prefix("test-wit").tempdir().unwrap();
        let oobi_root = Builder::new().prefix("test-wit-oobi").tempdir().unwrap();
        Witness::setup(
            witness_url.clone(),
            root_witness.path(),
            &oobi_root.path(),
            Some("ArwXoACJgOleVZ2PY7kXn7rA0II0mHYDhc6WrBH8fDAc".into()),
        )?
    });

    // Controller who will ask
    let mut asker_controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db1").tempdir().unwrap();
        std::fs::create_dir_all(root.path()).unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow1").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let oobi_root = Builder::new().prefix("oobi-test-db1").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager.clone(),
            oobi_root.path(),
        )
        .unwrap()
    };

    let asker_icp = asker_controller.incept(None, None, None).unwrap();

    // Controller about which we will ask
    let mut about_controller = {
        // Create test db and event processor.
        let root = Builder::new().prefix("test-db2").tempdir().unwrap();
        let db_controller = Arc::new(SledEventDatabase::new(root.path()).unwrap());

        let escrow_root = Builder::new().prefix("test-db-escrow2").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

        let oobi_root = Builder::new().prefix("oobi-test-db2").tempdir().unwrap();

        let key_manager = {
            use keri::signer::CryptoBox;
            Arc::new(Mutex::new(CryptoBox::new().unwrap()))
        };
        SimpleController::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager.clone(),
            oobi_root.path(),
        )
        .unwrap()
    };

    let about_icp = about_controller
        .incept(Some(vec![witness.prefix.clone()]), Some(0), None)
        .unwrap();

    witness
        .process_notice(Notice::Event(about_icp.clone()))
        .unwrap();

    let url = url::Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(
        url,
        root.path(),
        None,
        Box::new({
            FakeTransport {
                send_message: Box::new({
                    let witness = Arc::clone(&witness);
                    move |loc, msg| {
                        assert_eq!(&loc.url, &witness_url);
                        match msg {
                            Message::Notice(notice) => {
                                witness.process_notice(notice).unwrap();
                                Ok(vec![])
                            }
                            Message::Op(op) => {
                                let resp = witness.process_op(op).unwrap();
                                if let Some(resp) = resp {
                                    let s = resp.to_string();
                                    let msgs = parse_event_stream(s.as_bytes())
                                        .map_err(|_| TransportError::InvalidResponse)?;
                                    Ok(msgs)
                                } else {
                                    Ok(vec![])
                                }
                            }
                        }
                    }
                }),
            }
        }),
    )?;

    // Watcher should know both controllers
    watcher
        .parse_and_process_notices(&asker_icp.serialize().unwrap())
        .unwrap();
    watcher
        .parse_and_process_notices(&about_icp.serialize().unwrap())
        .unwrap();

    let query = asker_controller.query_ksn(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = futures::executor::block_on(watcher.process_op(query.clone()));

    assert!(matches!(err, Err(WatcherError::MissingRole { .. })));

    // Create and send end role oobi to watcher
    let end_role =
        asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix.clone()))?;
    futures::executor::block_on(watcher.process_op(end_role)).unwrap();

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query.clone()));
    // Expect error because no loc scheme for witness.
    assert!(matches!(
        result, Err(WatcherError::NoLocation { ref id })
        if id == &IdentifierPrefix::Basic(witness.prefix.clone())
    ));

    // Send witness' OOBI to watcher
    let witness_oobis = witness
        .oobi_manager
        .get_loc_scheme(&IdentifierPrefix::Basic(witness.prefix.clone()))
        .unwrap()
        .unwrap();
    let witness_oobi = SignedReply::new_nontrans(
        witness_oobis[0].clone(),
        witness.prefix.clone(),
        SelfSigning::Ed25519Sha512.derive(
            witness
                .signer
                .sign(witness_oobis[0].serialize().unwrap())
                .unwrap(),
        ),
    );
    // TODO: wrap in Message:Op and send to reply/ endpoint
    watcher.oobi_manager.process_oobi(&witness_oobi).unwrap();

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query));

    assert!(matches!(
        result,
        Ok(Some(PossibleResponse::Ksn(SignedReply { .. })))
    ));

    Ok(())
}
