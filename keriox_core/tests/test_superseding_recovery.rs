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
    // The superseded interaction does not come back.
    let _ = submit(&fx, &ixn2, &c.keys[0], None);
    assert_eq!(kel(&fx, &c.id())[2], digest(&after));
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
