use keri::error::Error;

mod controller_helper {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
    };

    use keri::{
        controller::event_generator,
        database::{escrow::EscrowDb, SledEventDatabase},
        derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
        error::Error,
        event::SerializationFormats,
        event_message::signed_event_message::{Notice, Op, SignedEventMessage},
        event_parsing::{message::key_event_message, EventType},
        oobi::{OobiManager, Role},
        prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix},
        processor::{
            basic_processor::BasicProcessor, escrow::default_escrow_bus,
            event_storage::EventStorage, Processor,
        },
        query::{
            query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
            reply_event::SignedReply,
        },
        signer::KeyManager,
    };

    /// Helper struct for events generation, signing and processing.
    pub struct Controller<K: KeyManager + 'static> {
        prefix: IdentifierPrefix,
        pub key_manager: Arc<Mutex<K>>,
        processor: BasicProcessor,
        oobi_manager: OobiManager,
        pub storage: EventStorage,
    }

    impl<K: KeyManager> Controller<K> {
        // incept a state and keys
        pub fn new(
            db: Arc<SledEventDatabase>,
            escrow_db: Arc<EscrowDb>,
            key_manager: Arc<Mutex<K>>,
            oobi_db_path: &Path,
        ) -> Result<Controller<K>, Error> {
            let (not_bus, _) = default_escrow_bus(db.clone(), escrow_db);
            let processor = BasicProcessor::new(db.clone(), Some(not_bus));

            Ok(Controller {
                prefix: IdentifierPrefix::default(),
                key_manager,
                oobi_manager: OobiManager::new(oobi_db_path),
                processor,
                storage: EventStorage::new(db),
            })
        }

        /// Getter of the instance prefix
        ///
        pub fn prefix(&self) -> &IdentifierPrefix {
            &self.prefix
        }

        pub fn incept(
            &mut self,
            initial_witness: Option<Vec<BasicPrefix>>,
            witness_threshold: Option<u64>,
        ) -> Result<SignedEventMessage, Error> {
            let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
            let icp = event_generator::incept(
                vec![Basic::Ed25519.derive(km.public_key())],
                vec![Basic::Ed25519.derive(km.next_public_key())],
                initial_witness.unwrap_or_default(),
                witness_threshold.unwrap_or(0),
            )
            .unwrap();
            let signature = km.sign(icp.as_bytes())?;
            let (_, key_event) = key_event_message(icp.as_bytes()).unwrap();
            let signed = if let EventType::KeyEvent(icp) = key_event {
                icp.sign(
                    vec![AttachedSignaturePrefix::new(
                        SelfSigning::Ed25519Sha512,
                        signature,
                        0,
                    )],
                    None,
                    None,
                )
            } else {
                unreachable!()
            };

            self.processor
                .process_notice(&Notice::Event(signed.clone()))?;

            self.prefix = signed.event_message.event.get_prefix();
            // No need to generate receipt

            Ok(signed)
        }

        pub fn query(&self, prefix: &IdentifierPrefix) -> Result<Op, Error> {
            let query_args = QueryArgs {
                s: None,
                i: prefix.clone(),
                src: None,
            };

            let qry = QueryEvent::new_query(
                QueryRoute::Ksn {
                    args: query_args,
                    reply_route: String::from(""),
                },
                SerializationFormats::JSON,
                &SelfAddressing::Blake3_256,
            )?;

            // sign message by bob
            let signature = AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                Arc::clone(&self.key_manager)
                    .lock()
                    .unwrap()
                    .sign(&serde_json::to_vec(&qry).unwrap())?,
                0,
            );
            // Qry message signed by Bob
            Ok(Op::Query(SignedQuery::new(
                qry,
                self.prefix().clone(),
                vec![signature],
            )))
        }

        pub fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<Op, Error> {
            let end_role =
                event_generator::generate_end_role(&self.prefix(), watcher_id, Role::Watcher, true)
                    .unwrap();
            let sed: Vec<u8> = end_role.serialize()?;
            let sig = self.key_manager.clone().lock().unwrap().sign(&sed)?;
            let att_sig = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, sig, 0);

            let oobi_rpy = SignedReply::new_trans(
                end_role,
                self.storage
                    .get_last_establishment_event_seal(self.prefix())?
                    .unwrap(),
                vec![att_sig],
            );
            self.oobi_manager.process_oobi(&oobi_rpy).unwrap();
            let signed_rpy = Op::Reply(oobi_rpy);

            Ok(signed_rpy)
        }
    }
}

#[test]
pub fn test_authentication() -> Result<(), Error> {
    use std::sync::{Arc, Mutex};

    use keri::database::{escrow::EscrowDb, SledEventDatabase};
    use keri::prefix::IdentifierPrefix;
    use tempfile::Builder;

    use crate::watcher::{WatcherData, WatcherError};

    use crate::test::controller_helper::Controller;

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
        Controller::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager.clone(),
            oobi_root.path(),
        )
        .unwrap()
    };

    let asker_icp = asker_controller
        .incept(None, None)
        .unwrap()
        .serialize()
        .unwrap();

    // Controller about witch we will ask
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
        Controller::new(
            Arc::clone(&db_controller),
            escrow_db,
            key_manager.clone(),
            oobi_root.path(),
        )
        .unwrap()
    };

    let about_icp = about_controller
        .incept(None, None)
        .unwrap()
        .serialize()
        .unwrap();

    let url = url::Url::parse("http://some/dummy/url").unwrap();
    let root = Builder::new().prefix("cont-test-db").tempdir().unwrap();
    let watcher = WatcherData::setup(url, root.path(), None)?;

    // Watcher should know bouth controllers
    watcher.parse_and_process_notices(&asker_icp).unwrap();
    watcher.parse_and_process_notices(&about_icp).unwrap();

    let query = asker_controller.query(about_controller.prefix())?;

    // Send query message to watcher before sending end role oobi
    let err = futures::executor::block_on(watcher.process_op(query.clone()));

    assert!(matches!(err, Err(WatcherError::MissingRole { role, id })));

    // Create and send end role oobi to watcher
    let end_role =
        asker_controller.add_watcher(&IdentifierPrefix::Basic(watcher.prefix.clone()))?;
    futures::executor::block_on(watcher.process_op(end_role)).unwrap();

    // Send query again
    let result = futures::executor::block_on(watcher.process_op(query));
    assert!(result.is_ok());

    Ok(())
}
