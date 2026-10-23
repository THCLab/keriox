//! An exchange message is only accepted when its sender signed it: the KERI
//! specification requires signatures attached to the message body. An
//! exchange without them must not reach anyone's mailbox.
#![cfg(feature = "mailbox")]

use std::sync::Arc;

use keri_core::{
    actor::{event_generator, process_notice, process_signed_exn, MaterialPath},
    database::redb::RedbDatabase,
    error::Error,
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder,
        msg::KeriEvent,
        signature::{Signature, SignerData},
        signed_event_message::Notice,
        EventTypeTag,
    },
    mailbox::exchange::{ForwardTopic, SignedExchange},
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    signer::Signer,
};
use tempfile::NamedTempFile;

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
}

fn setup() -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), None),
        storage: EventStorage::new_redb(db),
    }
}

/// A sender with signing threshold `kt`, known to the node.
fn sender(fx: &Fixture, signer: &Signer, kt: u64) -> KeriEvent<KeyEvent> {
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
        .with_threshold(&SignatureThreshold::Simple(kt))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()
        .unwrap();
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(icp.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(icp.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)),
        &fx.processor,
    )
    .unwrap();
    icp
}

/// An exchange forwarding `event` to `recipient`, with sender signatures
/// `signature`.
fn exchange(
    recipient: &IdentifierPrefix,
    event: &KeriEvent<KeyEvent>,
    signature: impl FnOnce(&[u8]) -> Vec<Signature>,
) -> SignedExchange {
    let exn = event_generator::exchange(
        &event.data.get_prefix(),
        recipient,
        event,
        ForwardTopic::Multisig,
        keri_core::event_message::keri_version::KeriVersion::V1,
    );
    let signature = signature(&exn.encode().unwrap());
    SignedExchange {
        exchange_message: exn,
        signature,
        data_signature: (MaterialPath::create_from_str("-a".into()).unwrap(), vec![]),
    }
}

fn recipient() -> IdentifierPrefix {
    IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()))
}

#[test]
fn an_exchange_without_sender_signatures_is_refused() {
    let fx = setup();
    let signer = Signer::new();
    let icp = sender(&fx, &signer, 1);

    let unsigned = exchange(&recipient(), &icp, |_| vec![]);
    assert!(matches!(
        process_signed_exn(unsigned, &fx.storage),
        Err(Error::MissingSignatures)
    ));
}

#[test]
fn an_empty_sender_signature_group_does_not_verify() {
    // kt=0 is met by any signature set, so an empty group would pass the
    // threshold; it must still carry a signature.
    for kt in [0, 1] {
        let fx = setup();
        let signer = Signer::new();
        let icp = sender(&fx, &signer, kt);
        let id = icp.data.get_prefix();

        let empty = exchange(&recipient(), &icp, |_| {
            vec![Signature::Transferable(
                SignerData::LastEstablishment(id.clone()),
                vec![],
            )]
        });
        assert!(
            process_signed_exn(empty, &fx.storage).is_err(),
            "kt={kt}"
        );
    }
}

#[test]
fn a_signed_exchange_is_accepted() {
    let fx = setup();
    let signer = Signer::new();
    let icp = sender(&fx, &signer, 1);
    let id = icp.data.get_prefix();

    let signed = exchange(&recipient(), &icp, |data| {
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(data).unwrap());
        vec![Signature::Transferable(
            SignerData::LastEstablishment(id.clone()),
            vec![IndexedSignature::new_both_same(sig, 0)],
        )]
    });
    process_signed_exn(signed, &fx.storage).unwrap();
}
