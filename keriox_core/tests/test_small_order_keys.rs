//! Small-order Ed25519 keys must never enter key state.
//!
//! For the identity point (and other small-order keys) the signature
//! R = identity, S = 0 passes permissive Ed25519 verification for every
//! message, so a key position holding such a key could be signed by anyone.
//! keripy (libsodium) rejects these keys and signatures; keriox must agree.

use std::sync::Arc;

use keri_core::{
    actor::{parse_event_stream, process_notice},
    database::redb::RedbDatabase,
    error::Error,
    event::sections::threshold::SignatureThreshold,
    event_message::{
        event_msg_builder::EventMsgBuilder,
        signed_event_message::{Message, Notice},
        EventTypeTag,
    },
    keys::PublicKey,
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use tempfile::NamedTempFile;

/// Compressed edwards25519 identity point.
fn identity_key() -> PublicKey {
    let mut key = vec![0u8; 32];
    key[0] = 1;
    PublicKey::new(key)
}

/// R = identity, S = 0: valid under permissive verification for the identity
/// key and any message.
fn universal_signature() -> SelfSigningPrefix {
    let mut sig = vec![0u8; 64];
    sig[0] = 1;
    SelfSigningPrefix::Ed25519Sha512(sig)
}

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

fn notice(raw: &[u8]) -> Notice {
    match parse_event_stream(raw).unwrap()[0].clone() {
        Message::Notice(n) => n,
        #[allow(unreachable_patterns)]
        _ => unreachable!(),
    }
}

fn sn(storage: &EventStorage<RedbDatabase>, id: &IdentifierPrefix) -> Option<u64> {
    storage.get_state(id).map(|state| state.sn)
}

/// Events produced by keripy: a group AID with k = [identity point, B],
/// kt = 1, incepted with B's signature, followed by an interaction event
/// carrying the universal signature at index 0, i.e. signed by no one.
#[test]
fn keripy_inception_with_small_order_key_is_rejected() {
    let (_path, processor, storage) = setup();

    let icp = notice(
        br#"{"v":"KERI10JSON00015a_","t":"icp","d":"EJ3IKlXS1rL-YeO_AJAiNCwKKq84y-Nx9tvrnHrRKM2j","i":"EJ3IKlXS1rL-YeO_AJAiNCwKKq84y-Nx9tvrnHrRKM2j","s":"0","kt":"1","k":["DAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","DPPbRtxXUymE0DrHXP1RBy73LHHtQ8jfV0xWPYYk8qK2"],"nt":"1","n":["EKfSipNpRZoJXqze6AzMHdXPi6LUYqqSG-p2Eo2C6CgV"],"bt":"0","b":[],"c":[],"a":[]}-KABABDjH6Wl34EVVq82JvLoibjiFY-WQxX8tJgJZMK1ezogQeZ7pQSssjtyMAE--jzHCKXiTHpXaDn960ZuUPPnE2cN"#,
    );
    let id = match &icp {
        Notice::Event(e) => e.event_message.data.get_prefix(),
        _ => unreachable!(),
    };
    let forged_ixn = notice(
        br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ELk2xuUQNkGOtd_SUbPUxHEtZ8D3uhPkyyBjtMeSRvNd","i":"EJ3IKlXS1rL-YeO_AJAiNCwKKq84y-Nx9tvrnHrRKM2j","s":"1","p":"EJ3IKlXS1rL-YeO_AJAiNCwKKq84y-Nx9tvrnHrRKM2j","a":[]}-KABAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"#,
    );

    assert!(matches!(
        process_notice(icp, &processor),
        Err(Error::InvalidPublicKey(_))
    ));
    assert_eq!(sn(&storage, &id), None);

    assert!(process_notice(forged_ixn, &processor).is_err());
    assert_eq!(sn(&storage, &id), None);
}

/// A controller committed to a small-order next key and now reveals it. The
/// rotation is rejected whether it is signed with the universal signature
/// for the small-order key or properly by the other member.
#[test]
fn rotation_to_small_order_key_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let weak = BasicPrefix::Ed25519(identity_key());
    let honest_next = BasicPrefix::Ed25519(next.public_key());

    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(current.public_key())])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![weak.clone(), honest_next.clone()])
        .with_next_threshold(&SignatureThreshold::Simple(1))
        .build()?;
    let id = icp.data.get_prefix();
    let icp_sig = SelfSigningPrefix::Ed25519Sha512(current.sign(icp.encode()?)?);
    process_notice(
        Notice::Event(icp.sign(
            vec![IndexedSignature::new_both_same(icp_sig, 0)],
            None,
            None,
        )),
        &processor,
    )?;
    assert_eq!(sn(&storage, &id), Some(0));

    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest()?)
        .with_keys(vec![weak.clone(), honest_next])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()?;

    let forged = rot.sign(
        vec![IndexedSignature::new_both_same(universal_signature(), 0)],
        None,
        None,
    );
    assert!(matches!(
        process_notice(Notice::Event(forged), &processor),
        Err(Error::InvalidPublicKey(key)) if key == weak
    ));
    assert_eq!(sn(&storage, &id), Some(0));

    let next_sig = SelfSigningPrefix::Ed25519Sha512(next.sign(rot.encode()?)?);
    let signed = rot.sign(
        vec![IndexedSignature::new_both_same(next_sig, 1)],
        None,
        None,
    );
    assert!(matches!(
        process_notice(Notice::Event(signed), &processor),
        Err(Error::InvalidPublicKey(key)) if key == weak
    ));
    assert_eq!(sn(&storage, &id), Some(0));

    Ok(())
}

/// Witness receipts are verified with the same Ed25519 check, so a
/// small-order witness key is rejected both at inception and when grafted
/// by a rotation.
#[test]
fn small_order_witness_is_rejected() -> Result<(), Error> {
    let (_path, processor, storage) = setup();
    let (current, next) = (Signer::new(), Signer::new());
    let weak_witness = BasicPrefix::Ed25519NT(identity_key());

    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(current.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(next.public_key())])
        .with_witness_list(&[weak_witness.clone()])
        .with_witness_threshold(&SignatureThreshold::Simple(1))
        .build()?;
    let icp_sig = SelfSigningPrefix::Ed25519Sha512(current.sign(icp.encode()?)?);
    assert!(matches!(
        process_notice(Notice::Event(icp.sign(
            vec![IndexedSignature::new_both_same(icp_sig, 0)],
            None,
            None,
        )), &processor),
        Err(Error::InvalidPublicKey(key)) if key == weak_witness
    ));
    assert_eq!(sn(&storage, &icp.data.get_prefix()), None);

    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(current.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(next.public_key())])
        .build()?;
    let id = icp.data.get_prefix();
    let icp_sig = SelfSigningPrefix::Ed25519Sha512(current.sign(icp.encode()?)?);
    process_notice(
        Notice::Event(icp.sign(
            vec![IndexedSignature::new_both_same(icp_sig, 0)],
            None,
            None,
        )),
        &processor,
    )?;
    assert_eq!(sn(&storage, &id), Some(0));

    let rot = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest()?)
        .with_keys(vec![BasicPrefix::Ed25519(next.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .with_witness_to_add(&[weak_witness.clone()])
        .with_witness_threshold(&SignatureThreshold::Simple(1))
        .build()?;
    let rot_sig = SelfSigningPrefix::Ed25519Sha512(next.sign(rot.encode()?)?);
    assert!(matches!(
        process_notice(Notice::Event(rot.sign(
            vec![IndexedSignature::new_both_same(rot_sig, 0)],
            None,
            None,
        )), &processor),
        Err(Error::InvalidPublicKey(key)) if key == weak_witness
    ));
    assert_eq!(sn(&storage, &id), Some(0));

    Ok(())
}
