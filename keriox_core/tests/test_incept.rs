use std::sync::Arc;

use cesrox::primitives::codes::basic::Basic;
use keri_core::{
    actor,
    database::SledEventDatabase,
    error::Error,
    event_message::{
        event_msg_builder::EventMsgBuilder, signed_event_message::Notice, EventTypeTag,
    },
    prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::{CryptoBox, KeyManager},
};
use tempfile::Builder;

#[test]
fn test_incept() -> Result<(), Error> {
    // Setup keys
    let key_manager = CryptoBox::new()?;
    let current_key = BasicPrefix::new(Basic::Ed25519, key_manager.public_key());
    let next_key = BasicPrefix::new(Basic::Ed25519, key_manager.next_public_key());

    // Setup events database
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let (processor, storage) = (
        BasicProcessor::new(db.clone(), None),
        EventStorage::new(db.clone()),
    );

    let inception_event = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![current_key])
        .with_next_keys(vec![next_key])
        .build()?;
    let identifier = inception_event.data.prefix.clone();
    let to_sign = inception_event.encode()?;
    let signature = key_manager.sign(&to_sign)?;
    let indexed_signature =
        IndexedSignature::new_both_same(SelfSigningPrefix::Ed25519Sha512(signature), 0);

    let signed_inception = inception_event.sign(vec![indexed_signature], None, None);

    actor::process_notice(Notice::Event(signed_inception), &processor)?;
    let state = storage.get_state(&identifier);
    assert!(matches!(state, Some(_)));
    assert_eq!(state.unwrap().sn, 0);

    Ok(())
}
