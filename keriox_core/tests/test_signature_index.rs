//! Signature and receipt indexes come from the wire, so an index outside the
//! key or witness list must be rejected as an error rather than panic the
//! processor: anyone can send such a message to a witness or watcher.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
    event::sections::{key_config::SignatureError, threshold::SignatureThreshold},
    event_message::{
        event_msg_builder::{EventMsgBuilder, ReceiptBuilder},
        signature::Nontransferable,
        signed_event_message::{Notice, SignedNontransferableReceipt},
        EventTypeTag,
    },
    prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
    state::WitnessConfig,
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

#[test]
fn event_signature_index_out_of_range_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let signer = Signer::new();

    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()?;
    let signature = SelfSigningPrefix::Ed25519Sha512(signer.sign(icp.encode()?)?);

    let result = process_notice(
        Notice::Event(icp.sign(
            vec![IndexedSignature::new_both_same(signature, 5)],
            None,
            None,
        )),
        &processor,
    );
    assert!(matches!(
        result,
        Err(Error::KeyConfigError(SignatureError::MissingIndex))
    ));
    assert!(storage.get_state(&icp.data.get_prefix()).is_none());

    Ok(())
}

#[test]
fn witness_receipt_index_out_of_range_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let (controller, witness) = (Signer::new(), Signer::new());

    // With a witness threshold of 0 the event is accepted without receipts,
    // so the receipt below reaches validation against the stored event.
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(controller.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .with_witness_list(&[BasicPrefix::Ed25519NT(witness.public_key())])
        .with_witness_threshold(&SignatureThreshold::Simple(0))
        .build()?;
    let id = icp.data.get_prefix();
    let signature = SelfSigningPrefix::Ed25519Sha512(controller.sign(icp.encode()?)?);
    process_notice(
        Notice::Event(icp.sign(
            vec![IndexedSignature::new_both_same(signature, 0)],
            None,
            None,
        )),
        &processor,
    )?;
    assert_eq!(storage.get_state(&id).map(|state| state.sn), Some(0));

    let receipt = ReceiptBuilder::default()
        .with_receipted_event(icp.clone())
        .build()?;
    let witness_signature = SelfSigningPrefix::Ed25519Sha512(witness.sign(icp.encode()?)?);
    let rct = SignedNontransferableReceipt::new(
        &receipt,
        vec![Nontransferable::Indexed(vec![
            IndexedSignature::new_current_only(witness_signature, 5),
        ])],
    );
    assert!(process_notice(Notice::NontransferableRct(rct), &processor).is_err());
    assert!(storage
        .get_nt_receipts(&id, 0)?
        .map_or(true, |rct| rct.signatures.is_empty()));

    Ok(())
}

#[test]
fn enough_receipts_ignores_index_out_of_range() {
    let witness = Signer::new();
    let config = WitnessConfig {
        tally: SignatureThreshold::Simple(1),
        witnesses: vec![BasicPrefix::Ed25519NT(witness.public_key())],
    };
    let signature = SelfSigningPrefix::Ed25519Sha512(witness.sign(b"event").unwrap());

    assert!(!config
        .enough_receipts(
            vec![],
            vec![IndexedSignature::new_current_only(signature.clone(), 5)],
        )
        .unwrap());
    assert!(config
        .enough_receipts(
            vec![],
            vec![IndexedSignature::new_current_only(signature, 0)],
        )
        .unwrap());
}
