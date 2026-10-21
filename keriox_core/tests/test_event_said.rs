//! An event's `d` field must be the digest of its content. Events reference
//! each other by that digest (`p`, seals, receipts, duplicity checks), so an
//! event signed with a `d` that belongs to different content must be
//! rejected, as keripy does, even though its signatures verify.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use tempfile::NamedTempFile;

fn setup() -> (
    NamedTempFile,
    BasicProcessor<RedbDatabase>,
    EventStorage<RedbDatabase>,
) {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    (
        path,
        BasicProcessor::new(db.clone(), None),
        EventStorage::new(db),
    )
}

/// Signs `event` with `signer` as the only controller key.
fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer) -> Result<Notice, Error> {
    let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode()?)?);
    Ok(Notice::Event(event.sign(
        vec![IndexedSignature::new_both_same(signature, 0)],
        None,
        None,
    )))
}

/// `event` with its `d` field replaced by `said`, reparsed so that it is the
/// message a peer would receive.
fn with_said(event: &KeriEvent<KeyEvent>, said: &str) -> KeriEvent<KeyEvent> {
    let raw = String::from_utf8(event.encode().unwrap()).unwrap();
    let real = format!("\"d\":\"{}\"", event.digest().unwrap());
    assert_eq!(real.len(), format!("\"d\":\"{said}\"").len());
    serde_json::from_str(&raw.replacen(&real, &format!("\"d\":\"{said}\""), 1)).unwrap()
}

fn incept(signer: &Signer) -> Result<KeriEvent<KeyEvent>, Error> {
    Ok(EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()?)
}

#[test]
fn interaction_with_foreign_said_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let signer = Signer::new();
    let icp = incept(&signer)?;
    process_notice(signed(&icp, &signer)?, &processor)?;
    let id = icp.data.get_prefix();

    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest()?)
        .build()?;
    let forged = with_said(&ixn, &icp.digest()?.to_string());

    let result = process_notice(signed(&forged, &signer)?, &processor);
    assert!(matches!(result, Err(Error::IncorrectDigest)), "{result:?}");
    assert_eq!(storage.get_state(&id).unwrap().sn, 0);

    // The same event with its own SAID is accepted.
    process_notice(signed(&ixn, &signer)?, &processor)?;
    assert_eq!(storage.get_state(&id).unwrap().sn, 1);
    Ok(())
}

#[test]
fn inception_with_basic_prefix_and_foreign_said_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let signer = Signer::new();
    let key = BasicPrefix::Ed25519(signer.public_key());
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_prefix(&IdentifierPrefix::Basic(key.clone()))
        .with_keys(vec![key])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()?;
    let other = incept(&Signer::new())?.digest()?.to_string();
    let forged = with_said(&icp, &other);

    let result = process_notice(signed(&forged, &signer)?, &processor);
    assert!(matches!(result, Err(Error::IncorrectDigest)), "{result:?}");
    assert!(storage.get_state(&icp.data.get_prefix()).is_none());

    process_notice(signed(&icp, &signer)?, &processor)?;
    assert_eq!(storage.get_state(&icp.data.get_prefix()).unwrap().sn, 0);
    Ok(())
}
