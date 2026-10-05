//! A witness counts once towards a weighted witness threshold however many
//! of its receipts arrive. Receipts are public, so otherwise anyone could
//! repeat one witness's receipt to meet a threshold meant for several.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::redb::RedbDatabase,
    error::Error,
    event::sections::threshold::SignatureThreshold,
    event::KeyEvent,
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signature::Nontransferable,
        signed_event_message::Notice, EventTypeTag,
    },
    prefix::{BasicPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
    signer::Signer,
};
use tempfile::NamedTempFile;

struct Setup {
    _path: NamedTempFile,
    processor: BasicProcessor<RedbDatabase>,
    storage: EventStorage<RedbDatabase>,
    controller: Signer,
    witnesses: [Signer; 2],
    icp: KeriEvent<KeyEvent>,
}

/// An inception with two witnesses, each weighing 1/2.
fn setup() -> Result<Setup, Error> {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    let (bus, _escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    let controller = Signer::new();
    let witnesses = [Signer::new(), Signer::new()];

    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![BasicPrefix::Ed25519(controller.public_key())])
        .with_next_keys(vec![BasicPrefix::Ed25519(Signer::new().public_key())])
        .with_witness_list(
            &witnesses
                .iter()
                .map(|w| BasicPrefix::Ed25519NT(w.public_key()))
                .collect::<Vec<_>>(),
        )
        .with_witness_threshold(&SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]))
        .build()?;

    Ok(Setup {
        _path: path,
        processor: BasicProcessor::new(db.clone(), Some(bus)),
        storage: EventStorage::new(db),
        controller,
        witnesses,
        icp,
    })
}

impl Setup {
    fn witness_signature(&self, witness: usize) -> SelfSigningPrefix {
        SelfSigningPrefix::Ed25519Sha512(
            self.witnesses[witness]
                .sign(self.icp.encode().unwrap())
                .unwrap(),
        )
    }

    fn indexed_receipt(&self, witness: usize) -> IndexedSignature {
        IndexedSignature::new_current_only(self.witness_signature(witness), witness as u16)
    }

    fn couplet_receipt(&self, witness: usize) -> (BasicPrefix, SelfSigningPrefix) {
        (
            BasicPrefix::Ed25519NT(self.witnesses[witness].public_key()),
            self.witness_signature(witness),
        )
    }

    /// Processes the inception with the given receipts attached and returns
    /// the resulting sn, if the event was accepted.
    fn process(&self, receipts: Vec<Nontransferable>) -> Result<Option<u64>, Error> {
        let signature = SelfSigningPrefix::Ed25519Sha512(self.controller.sign(self.icp.encode()?)?);
        process_notice(
            Notice::Event(self.icp.sign(
                vec![IndexedSignature::new_both_same(signature, 0)],
                Some(receipts),
                None,
            )),
            &self.processor,
        )?;
        Ok(self
            .storage
            .get_state(&self.icp.data.get_prefix())
            .map(|state| state.sn))
    }
}

#[test]
fn receipts_from_both_witnesses_meet_threshold() -> Result<(), Error> {
    let setup = setup()?;
    let receipts = vec![Nontransferable::Indexed(vec![
        setup.indexed_receipt(0),
        setup.indexed_receipt(1),
    ])];
    assert_eq!(setup.process(receipts)?, Some(0));
    Ok(())
}

#[test]
fn repeated_indexed_receipt_counts_once() -> Result<(), Error> {
    let setup = setup()?;
    let receipts = vec![Nontransferable::Indexed(vec![
        setup.indexed_receipt(0),
        setup.indexed_receipt(0),
    ])];
    assert_eq!(setup.process(receipts)?, None);
    Ok(())
}

#[test]
fn same_witness_as_couplet_and_indexed_counts_once() -> Result<(), Error> {
    let setup = setup()?;
    let receipts = vec![
        Nontransferable::Couplet(vec![setup.couplet_receipt(0)]),
        Nontransferable::Indexed(vec![setup.indexed_receipt(0)]),
    ];
    assert_eq!(setup.process(receipts)?, None);
    Ok(())
}
