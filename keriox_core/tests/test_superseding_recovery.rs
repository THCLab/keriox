//! Superseding recovery (KERI specification, Superseding Rules for Recovery
//! at a given location): a rotation may replace events a KEL already
//! accepted at its location, so a controller recovers from compromised
//! keys. Everything else at an occupied location stays duplicity. Every
//! case runs on the redb and the in-memory database, and on Postgres (at
//! DATABASE_URL) with the storage-postgres feature.

use std::sync::Arc;

use keri_core::{
    actor::process_notice,
    database::{
        memory::MemoryDatabase, redb::RedbDatabase, EscrowCreator, EventDatabase, QueryParameters,
    },
    error::Error,
    event::{
        sections::seal::{EventSeal, Seal, SourceSeal},
        KeyEvent,
    },
    event_message::{
        event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
        EventTypeTag,
    },
    prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        event_storage::EventStorage,
    },
    signer::Signer,
};
use tempfile::NamedTempFile;

trait Db: EventDatabase + EscrowCreator + Send + Sync + 'static {}
impl<D: EventDatabase + EscrowCreator + Send + Sync + 'static> Db for D {}

struct Fixture<D: Db> {
    _path: Option<NamedTempFile>,
    processor: BasicProcessor<D>,
    storage: EventStorage<D>,
    escrows: EscrowSet<D>,
}

fn fixture<D: Db>(db: D, path: Option<NamedTempFile>) -> Fixture<D> {
    let db = Arc::new(db);
    let (bus, escrows) = default_escrow_bus(db.clone(), EscrowConfig::default(), None);
    Fixture {
        _path: path,
        processor: BasicProcessor::new(db.clone(), Some(bus)),
        storage: EventStorage::new(db),
        escrows,
    }
}

fn redb() -> Fixture<RedbDatabase> {
    let path = NamedTempFile::new().unwrap();
    fixture(RedbDatabase::new(path.path()).unwrap(), Some(path))
}

fn memory() -> Fixture<MemoryDatabase> {
    fixture(MemoryDatabase::new(), None)
}

/// The database at DATABASE_URL, shared by the cases: each works on
/// identifiers of its own.
#[cfg(feature = "storage-postgres")]
fn postgres() -> Fixture<keri_core::database::postgres::PostgresDatabase> {
    use keri_core::database::postgres::PostgresDatabase;
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://postgres:postgres@localhost:5432/keri_test".into());
    let db = async_std::task::block_on(async {
        let db = PostgresDatabase::new(&url)
            .await
            .expect("connect to DATABASE_URL");
        db.run_migrations().await.expect("migrate");
        db
    });
    fixture(db, None)
}

/// Runs each case on every database.
macro_rules! on_each_database {
    ($($case:ident),* $(,)?) => {
        mod on_redb {
            $(#[test] fn $case() { super::$case(super::redb) })*
        }
        mod in_memory {
            $(#[test] fn $case() { super::$case(super::memory) })*
        }
        #[cfg(feature = "storage-postgres")]
        mod on_postgres {
            $(#[test] fn $case() { super::$case(super::postgres) })*
        }
    };
}

on_each_database!(
    a_rotation_supersedes_the_interactions_after_the_latest_rotation,
    an_interaction_before_a_rotation_is_not_superseded,
    a_rotation_does_not_supersede_a_rotation,
    an_interaction_supersedes_nothing,
    a_rotation_delegated_later_supersedes_the_latest_delegated_rotation,
    a_rotation_sealed_later_in_the_same_event_supersedes,
    a_rotation_anchored_by_the_delegators_recovery_supersedes,
    an_earlier_delegated_rotation_is_not_superseded,
    a_rotation_anchored_by_a_superseding_delegated_rotation_supersedes,
    a_witnessed_kel_is_recovered,
);

fn key(signer: &Signer) -> BasicPrefix {
    BasicPrefix::Ed25519(signer.public_key())
}

fn submit<D: Db>(
    fx: &Fixture<D>,
    event: &KeriEvent<KeyEvent>,
    signer: &Signer,
    seal: Option<SourceSeal>,
) -> Result<(), Error> {
    let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(event.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(event.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, seal)),
        &fx.processor,
    )
}

fn send<D: Db>(
    fx: &Fixture<D>,
    event: &KeriEvent<KeyEvent>,
    signer: &Signer,
    seal: Option<SourceSeal>,
) {
    submit(fx, event, signer, seal).unwrap();
}

/// The digests of the KEL of `id`, in order.
fn kel<D: Db>(fx: &Fixture<D>, id: &IdentifierPrefix) -> Vec<String> {
    fx.storage
        .events_db
        .get_kel_finalized_events(QueryParameters::All { id })
        .map(|events| {
            events
                .map(|e| {
                    e.signed_event_message
                        .event_message
                        .digest()
                        .unwrap()
                        .to_string()
                })
                .collect()
        })
        .unwrap_or_default()
}

fn digest(event: &KeriEvent<KeyEvent>) -> String {
    event.digest().unwrap().to_string()
}

/// The digests of every event the KEL of `id` accepted, in the order it
/// first saw them.
fn first_seen<D: Db>(fx: &Fixture<D>, id: &IdentifierPrefix) -> Vec<String> {
    fx.storage
        .events_db
        .get_first_seen(id)
        .map_err(|_| "first seen")
        .unwrap()
        .iter()
        .map(|d| d.to_string())
        .collect()
}

/// The digests of the disputed branch of `id`, in the order superseded.
fn disputed<D: Db>(fx: &Fixture<D>, id: &IdentifierPrefix) -> Vec<String> {
    fx.storage
        .get_disputed_events(id)
        .unwrap()
        .iter()
        .map(|e| {
            e.signed_event_message
                .event_message
                .digest()
                .unwrap()
                .to_string()
        })
        .collect()
}

fn duplicitous<D: Db>(fx: &Fixture<D>, id: &IdentifierPrefix) -> usize {
    fx.escrows.duplicitous.get(id).unwrap().len()
}

fn seal_of(event: &KeriEvent<KeyEvent>) -> Seal {
    Seal::Event(EventSeal::new(
        event.data.get_prefix(),
        event.data.get_sn(),
        event.digest().unwrap(),
    ))
}

fn source(event: &KeriEvent<KeyEvent>) -> Option<SourceSeal> {
    Some(SourceSeal::new(
        event.data.get_sn(),
        event.digest().unwrap(),
    ))
}

/// A KEL under construction: `keys[i]` is the key the `i`th establishment
/// event makes current.
struct Controller {
    keys: Vec<Signer>,
    icp: KeriEvent<KeyEvent>,
}

impl Controller {
    fn new<D: Db>(fx: &Fixture<D>) -> Self {
        let keys: Vec<Signer> = (0..6).map(|_| Signer::new()).collect();
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_keys(vec![key(&keys[0])])
            .with_next_keys(vec![key(&keys[1])])
            .build()
            .unwrap();
        send(fx, &icp, &keys[0], None);
        Controller { keys, icp }
    }

    fn id(&self) -> IdentifierPrefix {
        self.icp.data.get_prefix()
    }

    fn ixn(&self, sn: u64, prior: &KeriEvent<KeyEvent>, seals: Vec<Seal>) -> KeriEvent<KeyEvent> {
        EventMsgBuilder::new(EventTypeTag::Ixn)
            .with_prefix(&self.id())
            .with_sn(sn)
            .with_previous_event(&prior.digest().unwrap())
            .with_seal(seals)
            .build()
            .unwrap()
    }

    /// A rotation at `sn` after `prior` to `keys[to]`, committing to
    /// `next`.
    fn rot(
        &self,
        sn: u64,
        prior: &KeriEvent<KeyEvent>,
        to: usize,
        next: usize,
        seals: Vec<Seal>,
    ) -> KeriEvent<KeyEvent> {
        EventMsgBuilder::new(EventTypeTag::Rot)
            .with_prefix(&self.id())
            .with_sn(sn)
            .with_previous_event(&prior.digest().unwrap())
            .with_keys(vec![key(&self.keys[to])])
            .with_next_keys(vec![key(&self.keys[next])])
            .with_seal(seals)
            .build()
            .unwrap()
    }
}

/// A0: a rotation supersedes the interactions after the latest rotation.
/// The KEL continues from the rotation; the superseded events are off it.
fn a_rotation_supersedes_the_interactions_after_the_latest_rotation<D: Db>(
    setup: fn() -> Fixture<D>,
) {
    let fx = setup();
    let c = Controller::new(&fx);
    let ixn1 = c.ixn(1, &c.icp, vec![]);
    send(&fx, &ixn1, &c.keys[0], None);
    let ixn2 = c.ixn(2, &ixn1, vec![]);
    send(&fx, &ixn2, &c.keys[0], None);

    let recovery = c.rot(1, &c.icp, 1, 2, vec![]);
    send(&fx, &recovery, &c.keys[1], None);

    assert_eq!(kel(&fx, &c.id()), [digest(&c.icp), digest(&recovery)]);
    assert_eq!(fx.storage.get_state(&c.id()).unwrap().sn, 1);
    assert_eq!(duplicitous(&fx, &c.id()), 0);

    // The KEL goes on from the recovery, under the rotated keys.
    let after = c.ixn(2, &recovery, vec![]);
    send(&fx, &after, &c.keys[1], None);
    assert_eq!(kel(&fx, &c.id()).len(), 3);
    // The superseded interactions are the KEL's disputed branch: seen
    // already, so sent again they change nothing and are no duplicity.
    assert_eq!(disputed(&fx, &c.id()), [digest(&ixn1), digest(&ixn2)]);
    for superseded in [&ixn1, &ixn2] {
        submit(&fx, superseded, &c.keys[0], None).unwrap();
    }
    assert_eq!(kel(&fx, &c.id())[2], digest(&after));
    assert_eq!(duplicitous(&fx, &c.id()), 0);

    // The KEL was seen in the order icp, ixn1, ixn2, recovery, after: the
    // latest event is the fifth seen though its sn is 2.
    assert_eq!(
        first_seen(&fx, &c.id()),
        [&c.icp, &ixn1, &ixn2, &recovery, &after].map(digest)
    );
    let ksn = fx
        .storage
        .get_ksn_for_prefix(&c.id(), keri_core::event_message::keri_version::KeriVersion::V2_0)
        .unwrap();
    assert_eq!((ksn.state.sn, ksn.first_seen), (2, 4));
}

/// A0: an interaction that a later rotation follows is not superseded.
fn an_interaction_before_a_rotation_is_not_superseded<D: Db>(setup: fn() -> Fixture<D>) {
    let fx = setup();
    let c = Controller::new(&fx);
    let ixn1 = c.ixn(1, &c.icp, vec![]);
    send(&fx, &ixn1, &c.keys[0], None);
    let rot2 = c.rot(2, &ixn1, 1, 2, vec![]);
    send(&fx, &rot2, &c.keys[1], None);
    let before = kel(&fx, &c.id());

    let late = c.rot(1, &c.icp, 1, 3, vec![]);
    let _ = submit(&fx, &late, &c.keys[1], None);

    assert_eq!(kel(&fx, &c.id()), before);
    assert_eq!(duplicitous(&fx, &c.id()), 1);
}

/// A1: a non-delegated rotation does not supersede a rotation.
fn a_rotation_does_not_supersede_a_rotation<D: Db>(setup: fn() -> Fixture<D>) {
    let fx = setup();
    let c = Controller::new(&fx);
    let rot1 = c.rot(1, &c.icp, 1, 2, vec![]);
    send(&fx, &rot1, &c.keys[1], None);

    let other = c.rot(1, &c.icp, 1, 3, vec![]);
    let _ = submit(&fx, &other, &c.keys[1], None);

    assert_eq!(kel(&fx, &c.id()), [digest(&c.icp), digest(&rot1)]);
    assert_eq!(duplicitous(&fx, &c.id()), 1);
}

/// A2: an interaction supersedes nothing.
fn an_interaction_supersedes_nothing<D: Db>(setup: fn() -> Fixture<D>) {
    let fx = setup();
    let c = Controller::new(&fx);
    let ixn1 = c.ixn(1, &c.icp, vec![]);
    send(&fx, &ixn1, &c.keys[0], None);

    let other = c.ixn(1, &c.icp, vec![seal_of(&c.icp)]);
    let _ = submit(&fx, &other, &c.keys[0], None);

    assert_eq!(kel(&fx, &c.id()), [digest(&c.icp), digest(&ixn1)]);
    assert_eq!(duplicitous(&fx, &c.id()), 1);
}

/// A delegated identifier under a delegator, with its inception accepted.
struct Delegation {
    delegator: Controller,
    keys: Vec<Signer>,
    dip: KeriEvent<KeyEvent>,
    /// The delegator's latest event.
    last: KeriEvent<KeyEvent>,
}

impl Delegation {
    fn new<D: Db>(fx: &Fixture<D>) -> Self {
        let delegator = Controller::new(fx);
        let keys: Vec<Signer> = (0..5).map(|_| Signer::new()).collect();
        let dip = EventMsgBuilder::new(EventTypeTag::Dip)
            .with_delegator(&delegator.id())
            .with_keys(vec![key(&keys[0])])
            .with_next_keys(vec![key(&keys[1])])
            .build()
            .unwrap();
        let anchor = delegator.ixn(1, &delegator.icp, vec![seal_of(&dip)]);
        send(fx, &anchor, &delegator.keys[0], None);
        send(fx, &dip, &keys[0], source(&anchor));
        Delegation {
            delegator,
            keys,
            dip,
            last: anchor,
        }
    }

    fn id(&self) -> IdentifierPrefix {
        self.dip.data.get_prefix()
    }

    /// A delegated rotation at sn 1 to `keys[1]`, committing to `next`.
    fn drt(&self, next: usize) -> KeriEvent<KeyEvent> {
        self.drt_after(1, &self.dip, 1, next)
    }

    fn drt_after(
        &self,
        sn: u64,
        prior: &KeriEvent<KeyEvent>,
        to: usize,
        next: usize,
    ) -> KeriEvent<KeyEvent> {
        EventMsgBuilder::new(EventTypeTag::Drt)
            .with_prefix(&self.id())
            .with_sn(sn)
            .with_previous_event(&prior.digest().unwrap())
            .with_keys(vec![key(&self.keys[to])])
            .with_next_keys(vec![key(&self.keys[next])])
            .build()
            .unwrap()
    }

    /// The delegator's next interaction, anchoring `seals`.
    fn anchor<D: Db>(&mut self, fx: &Fixture<D>, seals: Vec<Seal>) -> KeriEvent<KeyEvent> {
        let ixn = self
            .delegator
            .ixn(self.last.data.get_sn() + 1, &self.last, seals);
        send(fx, &ixn, &self.delegator.keys[0], None);
        self.last = ixn.clone();
        ixn
    }
}

/// B1: a delegated rotation the delegator anchored in a later event
/// supersedes the latest delegated rotation; one anchored earlier does
/// not.
fn a_rotation_delegated_later_supersedes_the_latest_delegated_rotation<D: Db>(
    setup: fn() -> Fixture<D>,
) {
    let fx = setup();
    let mut d = Delegation::new(&fx);
    let (first, second) = (d.drt(2), d.drt(3));
    let anchor_first = d.anchor(&fx, vec![seal_of(&first)]);
    let anchor_second = d.anchor(&fx, vec![seal_of(&second)]);

    send(&fx, &first, &d.keys[1], source(&anchor_first));
    send(&fx, &second, &d.keys[1], source(&anchor_second));
    assert_eq!(kel(&fx, &d.id()), [digest(&d.dip), digest(&second)]);
    assert_eq!(disputed(&fx, &d.id()), [digest(&first)]);
    submit(&fx, &first, &d.keys[1], source(&anchor_first)).unwrap();
    assert_eq!(kel(&fx, &d.id()), [digest(&d.dip), digest(&second)]);
    assert_eq!(duplicitous(&fx, &d.id()), 0);

    // The other way round: anchored earlier, it does not supersede.
    let fx = setup();
    let mut d = Delegation::new(&fx);
    let (first, second) = (d.drt(2), d.drt(3));
    let anchor_second = d.anchor(&fx, vec![seal_of(&second)]);
    let anchor_first = d.anchor(&fx, vec![seal_of(&first)]);
    send(&fx, &first, &d.keys[1], source(&anchor_first));
    let _ = submit(&fx, &second, &d.keys[1], source(&anchor_second));
    assert_eq!(kel(&fx, &d.id()), [digest(&d.dip), digest(&first)]);
    assert_eq!(duplicitous(&fx, &d.id()), 1);
}

/// B2: within one delegating event, the rotation whose seal comes later
/// supersedes.
fn a_rotation_sealed_later_in_the_same_event_supersedes<D: Db>(setup: fn() -> Fixture<D>) {
    for later_seal_wins in [true, false] {
        let fx = setup();
        let mut d = Delegation::new(&fx);
        let (accepted, other) = (d.drt(2), d.drt(3));
        let seals = if later_seal_wins {
            vec![seal_of(&accepted), seal_of(&other)]
        } else {
            vec![seal_of(&other), seal_of(&accepted)]
        };
        let anchor = d.anchor(&fx, seals);
        send(&fx, &accepted, &d.keys[1], source(&anchor));
        let _ = submit(&fx, &other, &d.keys[1], source(&anchor));
        let expected = if later_seal_wins { &other } else { &accepted };
        assert_eq!(
            kel(&fx, &d.id()),
            [digest(&d.dip), digest(expected)],
            "later seal wins: {later_seal_wins}"
        );
    }
}

/// B3: when the delegator recovers by superseding the interaction that
/// anchored a delegated rotation, the rotation its recovery anchors
/// supersedes that delegated rotation.
fn a_rotation_anchored_by_the_delegators_recovery_supersedes<D: Db>(setup: fn() -> Fixture<D>) {
    let fx = setup();
    let mut d = Delegation::new(&fx);
    let (compromised, recovered) = (d.drt(2), d.drt(3));
    let before = d.last.clone();
    let anchor = d.anchor(&fx, vec![seal_of(&compromised)]);
    send(&fx, &compromised, &d.keys[1], source(&anchor));

    // The delegator rotates over its own anchoring interaction.
    let recovery = d.delegator.rot(
        anchor.data.get_sn(),
        &before,
        1,
        2,
        vec![seal_of(&recovered)],
    );
    send(&fx, &recovery, &d.delegator.keys[1], None);
    assert_eq!(
        kel(&fx, &d.delegator.id()).last().unwrap(),
        &digest(&recovery)
    );

    send(&fx, &recovered, &d.keys[1], source(&recovery));
    assert_eq!(kel(&fx, &d.id()), [digest(&d.dip), digest(&recovered)]);
}

/// B: only the latest delegated rotation may be superseded.
fn an_earlier_delegated_rotation_is_not_superseded<D: Db>(setup: fn() -> Fixture<D>) {
    let fx = setup();
    let mut d = Delegation::new(&fx);
    let first = d.drt(2);
    let then = d.drt_after(2, &first, 2, 3);
    let late = d.drt(4);
    let a1 = d.anchor(&fx, vec![seal_of(&first)]);
    let a2 = d.anchor(&fx, vec![seal_of(&then)]);
    let a3 = d.anchor(&fx, vec![seal_of(&late)]);
    send(&fx, &first, &d.keys[1], source(&a1));
    send(&fx, &then, &d.keys[2], source(&a2));

    let _ = submit(&fx, &late, &d.keys[1], source(&a3));

    assert_eq!(
        kel(&fx, &d.id()),
        [digest(&d.dip), digest(&first), digest(&then)]
    );
}

/// C: when the delegator is itself delegated, its own superseding recovery
/// counts too. Here a root approves two competing rotations of a middle
/// identifier, each anchoring one of two competing rotations of a delegate;
/// the root's later approval lets the middle's second rotation supersede
/// its first, and so the delegate's rotation it anchors supersedes as well.
fn a_rotation_anchored_by_a_superseding_delegated_rotation_supersedes<D: Db>(
    setup: fn() -> Fixture<D>,
) {
    let fx = setup();
    let mut middle = Delegation::new(&fx);
    let middle_id = middle.id();
    let keys: Vec<Signer> = (0..4).map(|_| Signer::new()).collect();
    let dip = EventMsgBuilder::new(EventTypeTag::Dip)
        .with_delegator(&middle_id)
        .with_keys(vec![key(&keys[0])])
        .with_next_keys(vec![key(&keys[1])])
        .build()
        .unwrap();
    let middle_ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&middle_id)
        .with_sn(1)
        .with_previous_event(&middle.dip.digest().unwrap())
        .with_seal(vec![seal_of(&dip)])
        .build()
        .unwrap();
    send(&fx, &middle_ixn, &middle.keys[0], None);
    send(&fx, &dip, &keys[0], source(&middle_ixn));
    let id = dip.data.get_prefix();

    let delegate_rot = |next: usize| {
        EventMsgBuilder::new(EventTypeTag::Drt)
            .with_prefix(&id)
            .with_sn(1)
            .with_previous_event(&dip.digest().unwrap())
            .with_keys(vec![key(&keys[1])])
            .with_next_keys(vec![key(&keys[next])])
            .build()
            .unwrap()
    };
    let (compromised, recovered) = (delegate_rot(2), delegate_rot(3));
    let middle_rot = |next: usize, anchored: &KeriEvent<KeyEvent>| {
        EventMsgBuilder::new(EventTypeTag::Drt)
            .with_prefix(&middle_id)
            .with_sn(2)
            .with_previous_event(&middle_ixn.digest().unwrap())
            .with_keys(vec![key(&middle.keys[1])])
            .with_next_keys(vec![key(&middle.keys[next])])
            .with_seal(vec![seal_of(anchored)])
            .build()
            .unwrap()
    };
    let (middle_first, middle_second) = (middle_rot(2, &compromised), middle_rot(3, &recovered));

    let root_first = middle.anchor(&fx, vec![seal_of(&middle_first)]);
    send(&fx, &middle_first, &middle.keys[1], source(&root_first));
    send(&fx, &compromised, &keys[1], source(&middle_first));
    assert_eq!(kel(&fx, &id), [digest(&dip), digest(&compromised)]);

    // The root approves the middle's second rotation later (B1).
    let root_second = middle.anchor(&fx, vec![seal_of(&middle_second)]);
    send(&fx, &middle_second, &middle.keys[1], source(&root_second));
    assert_eq!(
        kel(&fx, &middle_id).last().unwrap(),
        &digest(&middle_second)
    );

    // So the delegate's rotation it anchors supersedes (C).
    send(&fx, &recovered, &keys[1], source(&middle_second));
    assert_eq!(kel(&fx, &id), [digest(&dip), digest(&recovered)]);
    assert_eq!(disputed(&fx, &id), [digest(&compromised)]);
}

/// A KEL with witnesses accepts each event once it has its receipts, and so
/// does it a recovery rotation, with receipts of its own: those of the
/// interaction it supersedes do not count for it. The first-seen numbers
/// count every event the KEL accepted, in the order it accepted them.
fn a_witnessed_kel_is_recovered<D: Db>(setup: fn() -> Fixture<D>) {
    use keri_core::event::sections::threshold::SignatureThreshold;
    use keri_core::event_message::signature::Nontransferable;

    let fx = setup();
    let keys: Vec<Signer> = (0..3).map(|_| Signer::new()).collect();
    let witness = Signer::new();
    let witness_id = BasicPrefix::Ed25519NT(witness.public_key());
    let one = SignatureThreshold::Simple(1);
    let witnessed = |event: &KeriEvent<KeyEvent>, signer: &Signer| {
        let encoded = event.encode().unwrap();
        let sig = SelfSigningPrefix::Ed25519Sha512(signer.sign(&encoded).unwrap());
        let receipt = SelfSigningPrefix::Ed25519Sha512(witness.sign(&encoded).unwrap());
        process_notice(
            Notice::Event(event.sign(
                vec![IndexedSignature::new_both_same(sig, 0)],
                Some(vec![Nontransferable::Couplet(vec![(
                    witness_id.clone(),
                    receipt,
                )])]),
                None,
            )),
            &fx.processor,
        )
        .unwrap();
    };
    let icp = EventMsgBuilder::new(EventTypeTag::Icp)
        .with_keys(vec![key(&keys[0])])
        .with_next_keys(vec![key(&keys[1])])
        .with_witness_list(&[witness_id.clone()])
        .with_witness_threshold(&one)
        .build()
        .unwrap();
    witnessed(&icp, &keys[0]);
    let id = icp.data.get_prefix();
    let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .build()
        .unwrap();
    witnessed(&ixn, &keys[0]);
    assert_eq!(kel(&fx, &id), [digest(&icp), digest(&ixn)]);

    let recovery = EventMsgBuilder::new(EventTypeTag::Rot)
        .with_prefix(&id)
        .with_sn(1)
        .with_previous_event(&icp.digest().unwrap())
        .with_keys(vec![key(&keys[1])])
        .with_next_keys(vec![key(&keys[2])])
        .with_witness_threshold(&one)
        .build()
        .unwrap();
    let sig = SelfSigningPrefix::Ed25519Sha512(keys[1].sign(recovery.encode().unwrap()).unwrap());
    process_notice(
        Notice::Event(recovery.sign(vec![IndexedSignature::new_both_same(sig, 0)], None, None)),
        &fx.processor,
    )
    .unwrap();
    // Not witnessed yet: the interaction's receipt is not the recovery's.
    assert_eq!(kel(&fx, &id), [digest(&icp), digest(&ixn)]);

    let receipt = keri_core::event::receipt::Receipt::new(
        keri_core::event_message::keri_version::KeriVersion::of(&recovery.serialization_info),
        said::version::format::SerializationFormats::JSON,
        recovery.digest().unwrap(),
        id.clone(),
        1,
    );
    let witness_sig =
        SelfSigningPrefix::Ed25519Sha512(witness.sign(recovery.encode().unwrap()).unwrap());
    process_notice(
        Notice::NontransferableRct(
            keri_core::event_message::signed_event_message::SignedNontransferableReceipt::new(
                &receipt,
                vec![Nontransferable::Couplet(vec![(
                    witness_id.clone(),
                    witness_sig,
                )])],
            ),
        ),
        &fx.processor,
    )
    .unwrap();

    assert_eq!(kel(&fx, &id), [digest(&icp), digest(&recovery)]);
    assert_eq!(disputed(&fx, &id), [digest(&ixn)]);
    assert_eq!(
        first_seen(&fx, &id),
        [digest(&icp), digest(&ixn), digest(&recovery)]
    );
}
