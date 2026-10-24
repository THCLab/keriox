//! Escrows drop the events they held longer than their timeout, so that
//! events whose missing pieces never arrive do not stay in them for good.

use std::{sync::Arc, thread, time::Duration};

use tempfile::NamedTempFile;

use crate::{
    database::{redb::RedbDatabase, EscrowDatabase},
    event::{sections::threshold::SignatureThreshold, KeyEvent},
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        event_storage::EventStorage,
        Processor,
    },
    signer::Signer,
};

struct Fixture {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    escrows: EscrowSet<RedbDatabase>,
}

fn setup(timeout: Duration) -> Fixture {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let config = EscrowConfig {
        out_of_order_timeout: timeout,
        partially_signed_timeout: timeout,
        partially_witnessed_timeout: timeout,
        trans_receipt_timeout: timeout,
        delegation_timeout: timeout,
    };
    let (bus, escrows) = default_escrow_bus(db.clone(), config, None);
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), Some(bus)),
        storage: EventStorage::new(db),
        escrows,
    }
}

fn signed(event: &KeriEvent<KeyEvent>, signer: &Signer) -> Notice {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None))
}

/// An inception and two interactions after it, signed by `signer`.
fn kel(signer: &Signer) -> (IdentifierPrefix, Vec<Notice>) {
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
        .with_threshold(&SignatureThreshold::Simple(1))
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .build()
        .unwrap();
    let id = icp.data.get_prefix();
    let mut events = vec![icp];
    for sn in 1..=2 {
        let previous = events.last().unwrap().digest().unwrap();
        events.push(
            EventMsgBuilder::new(EventTypeTag::Ixn)
                .with_prefix(&id)
                .with_sn(sn)
                .with_previous_event(&previous)
                .build()
                .unwrap(),
        );
    }
    (id, events.iter().map(|ev| signed(ev, signer)).collect())
}

/// Processes the KEL with its last event first, waiting `wait` before the
/// rest arrives. Returns the sn the KEL reaches.
fn last_event_first(timeout: Duration, wait: Duration) -> (u64, usize) {
    let fx = setup(timeout);
    let signer = Signer::new();
    let (id, events) = kel(&signer);
    fx.processor.process_notice(&events[2]).unwrap();
    thread::sleep(wait);
    fx.processor.process_notice(&events[0]).unwrap();
    fx.processor.process_notice(&events[1]).unwrap();
    let escrowed = fx
        .escrows
        .out_of_order
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap()
        .count();
    (fx.storage.get_state(&id).unwrap().sn, escrowed)
}

#[test]
fn an_out_of_order_event_is_kept_until_its_timeout() {
    assert_eq!(
        last_event_first(Duration::from_secs(60), Duration::ZERO),
        (2, 0)
    );
}

#[test]
fn an_out_of_order_event_held_past_its_timeout_is_dropped() {
    assert_eq!(
        last_event_first(Duration::from_secs(1), Duration::from_secs(2)),
        (1, 0)
    );
}

#[test]
fn escrows_keep_events_for_fifteen_minutes_by_default() {
    let config = EscrowConfig::default();
    for timeout in [
        config.out_of_order_timeout,
        config.partially_signed_timeout,
        config.partially_witnessed_timeout,
        config.trans_receipt_timeout,
        config.delegation_timeout,
    ] {
        assert_eq!(timeout, Duration::from_secs(15 * 60));
    }
}
