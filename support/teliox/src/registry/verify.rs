//! Verifying a registry: the state its presented events establish, given
//! the Issuer's KEL. It fetches nothing and concludes only from the
//! evidence, as keripy's `vet` does: every presented event must be anchored
//! in the Issuer's KEL, the chain must run from the inception without gaps,
//! and two anchored events at one position are duplicity.
//!
//! Anchors are matched by digest, so any seal whose `d` is the event's SAID
//! anchors it. When the Issuer anchors with event seals naming the registry
//! and position, as keripy issuers do, a registry is also refused as stale
//! if the KEL names a later position than the presented head. keriox
//! issuers anchor with digest seals, which say nothing of the registry, so
//! for their registries the state is as presented: nothing here proves that
//! no later update exists.

use std::collections::HashMap;

use chrono::{DateTime, FixedOffset};
use keri_core::{
    database::{EventDatabase, QueryParameters},
    event::sections::seal::Seal,
    prefix::IdentifierPrefix,
    processor::event_storage::EventStorage,
};
use said::SelfAddressingIdentifier;

use super::{RegistryError, RegistryIlk, RegistryMessage, StateBlock};

/// What a presented ACDC says about itself, to bind it to a registry.
#[derive(Debug, Clone, PartialEq)]
pub struct AcdcBinding {
    /// The ACDC's SAID, its top-level `d`.
    pub said: SelfAddressingIdentifier,
    /// Its Issuer, `i`.
    pub issuer: IdentifierPrefix,
    /// The registry it names in `rd`, if it names one.
    pub registry: Option<SelfAddressingIdentifier>,
}

/// How a presented ACDC is bound to its registry.
#[derive(Debug, Clone, PartialEq)]
pub enum Binding {
    /// The registry names the ACDC and the ACDC names the registry.
    Mutual,
    /// The registry names the ACDC; the ACDC names no registry.
    OneWay,
}

/// The verified state of a registry.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryState {
    pub registry: SelfAddressingIdentifier,
    pub issuer: IdentifierPrefix,
    /// The latest verified event.
    pub head: SelfAddressingIdentifier,
    pub sn: u64,
    pub ilk: RegistryIlk,
    /// The transaction ACDC of the head, once disclosed; `None` while
    /// blinded or for a placeholder.
    pub acdc: Option<SelfAddressingIdentifier>,
    /// The state of the head, once disclosed; `None` while blinded or for a
    /// placeholder.
    pub state: Option<String>,
    pub timestamp: DateTime<FixedOffset>,
    /// How the presented ACDC binds to the registry, when one was given.
    pub binding: Option<Binding>,
    /// The Issuer's key event anchoring each event of the chain: its sn and
    /// SAID.
    pub anchors: Vec<(u64, SelfAddressingIdentifier)>,
}

fn chain(message: String) -> RegistryError {
    RegistryError::Chain(message)
}

/// Verifies the registry whose inception is `inception` and whose updates
/// are `updates`, in any order, against the Issuer's KEL in `kel`.
/// `block` is the disclosed state block of the head, `acdc` the presented
/// ACDC to bind to it.
pub fn verify<D: EventDatabase>(
    kel: &EventStorage<D>,
    inception: &RegistryMessage,
    updates: &[RegistryMessage],
    block: Option<&StateBlock>,
    acdc: Option<&AcdcBinding>,
) -> Result<RegistryState, RegistryError> {
    let Some(issuer) = inception.issuer() else {
        return Err(chain("the first event is not a registry inception".into()));
    };
    let issuer = issuer?;
    let registry = inception.said()?;
    for update in updates {
        if update.ilk() == RegistryIlk::Rip {
            return Err(chain("a registry has one inception".into()));
        }
        if update.registry()? != registry {
            return Err(chain(format!(
                "update {} belongs to registry {}, not {registry}",
                update.said()?,
                update.registry()?
            )));
        }
    }

    let seals = IssuerSeals::read(kel, &issuer);
    let mut anchors = vec![seals.anchor(&registry)?];
    let mut head = inception;
    let mut remaining: Vec<&RegistryMessage> = updates.iter().collect();
    let mut n = 1;
    while !remaining.is_empty() {
        let at_n: Vec<&RegistryMessage> =
            remaining.iter().copied().filter(|u| u.sn() == n).collect();
        if at_n.is_empty() {
            return Err(chain(format!(
                "registry {registry} has no update at n={n:x} but has later ones"
            )));
        }
        let prior = head.said()?;
        let mut distinct: Vec<(SelfAddressingIdentifier, &RegistryMessage)> = vec![];
        for update in at_n {
            let said = update.said()?;
            if update.prior().transpose()?.as_ref() != Some(&prior) {
                return Err(chain(format!(
                    "update {said} at n={n:x} does not follow {prior}"
                )));
            }
            if !distinct.iter().any(|(seen, _)| seen == &said) {
                distinct.push((said, update));
            }
        }
        // Every event must be anchored before any conclusion.
        let couples = distinct
            .iter()
            .map(|(said, _)| seals.anchor(said))
            .collect::<Result<Vec<_>, _>>()?;
        if distinct.len() > 1 {
            return Err(RegistryError::Duplicity(format!(
                "registry {registry} has {} anchored updates at n={n:x}",
                distinct.len()
            )));
        }
        head = distinct[0].1;
        anchors.push(couples[0].clone());
        remaining.retain(|update| update.sn() != n);
        n += 1;
    }

    if let Some(later) = seals.later_position(&registry, head.sn()) {
        return Err(RegistryError::Stale(format!(
            "the Issuer anchored update n={later:x} of registry {registry}, the presented \
             registry ends at n={:x}",
            head.sn()
        )));
    }

    let disclosed = match head.ilk() {
        RegistryIlk::Rip => None,
        RegistryIlk::Bup => {
            let blid = head.blid().transpose()?;
            match block {
                Some(block) if Some(block.blid()?) == blid => {
                    Some((block.acdc()?, block.state().to_string()))
                }
                Some(_) => {
                    return Err(RegistryError::Blind(format!(
                        "the disclosed block is not the block behind the head's BLID {}",
                        blid.map(|b| b.to_string()).unwrap_or_default()
                    )))
                }
                None => None,
            }
        }
        RegistryIlk::Upd => head
            .disclosed()
            .transpose()?
            .map(|(acdc, state)| (Some(acdc), state)),
    };
    let (head_acdc, state) = match disclosed {
        Some((acdc, state)) => (acdc, Some(state).filter(|s| !s.is_empty())),
        None => (None, None),
    };

    let binding = match acdc {
        None => None,
        Some(presented) => {
            if head.ilk() == RegistryIlk::Bup && block.is_none() {
                return Err(RegistryError::Blind(format!(
                    "the head of registry {registry} is blinded and no state was disclosed"
                )));
            }
            if head_acdc.as_ref() != Some(&presented.said) {
                return Err(RegistryError::Binding(format!(
                    "the registry state is not of ACDC {}",
                    presented.said
                )));
            }
            if presented.issuer != issuer {
                return Err(RegistryError::Binding(format!(
                    "ACDC issuer {} is not registry issuer {issuer}",
                    presented.issuer
                )));
            }
            Some(match &presented.registry {
                Some(named) if named == &registry => Binding::Mutual,
                Some(named) => {
                    return Err(RegistryError::Binding(format!(
                        "ACDC names registry {named}, not {registry}"
                    )))
                }
                None => Binding::OneWay,
            })
        }
    };

    Ok(RegistryState {
        registry,
        issuer,
        head: head.said()?,
        sn: head.sn(),
        ilk: head.ilk(),
        acdc: head_acdc,
        state,
        timestamp: head.timestamp()?,
        binding,
        anchors,
    })
}

/// The seals of the Issuer's accepted key events.
struct IssuerSeals {
    /// Sealed digest to the (sn, SAID) of the first key event sealing it.
    by_digest: HashMap<SelfAddressingIdentifier, (u64, SelfAddressingIdentifier)>,
    /// The positions event seals name, per sealed identifier.
    positions: HashMap<IdentifierPrefix, Vec<u64>>,
}

impl IssuerSeals {
    fn read<D: EventDatabase>(kel: &EventStorage<D>, issuer: &IdentifierPrefix) -> Self {
        let mut seals = IssuerSeals {
            by_digest: HashMap::new(),
            positions: HashMap::new(),
        };
        let events = kel
            .events_db
            .get_kel_finalized_events(QueryParameters::All { id: issuer })
            .into_iter()
            .flatten();
        for event in events {
            let message = event.signed_event_message.event_message;
            let Ok(said) = message.digest() else { continue };
            for seal in message.data.get_event_data().seals() {
                if let Some(digest) = seal.sealed_digest() {
                    seals
                        .by_digest
                        .entry(digest)
                        .or_insert((message.data.get_sn(), said.clone()));
                }
                if let Seal::Event(event_seal) = seal {
                    seals
                        .positions
                        .entry(event_seal.prefix.clone())
                        .or_default()
                        .push(event_seal.sn);
                }
            }
        }
        seals
    }

    /// The Issuer's key event anchoring `said`.
    fn anchor(
        &self,
        said: &SelfAddressingIdentifier,
    ) -> Result<(u64, SelfAddressingIdentifier), RegistryError> {
        self.by_digest
            .get(said)
            .cloned()
            .ok_or_else(|| RegistryError::MissingAnchor(said.clone()))
    }

    /// A position after `sn` that an event seal names for `registry`.
    fn later_position(&self, registry: &SelfAddressingIdentifier, sn: u64) -> Option<u64> {
        self.positions
            .get(&IdentifierPrefix::SelfAddressing(registry.clone().into()))?
            .iter()
            .copied()
            .filter(|position| *position > sn)
            .max()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use chrono::{Duration, TimeZone, Utc};
    use keri_core::{
        database::redb::RedbDatabase,
        event::{
            sections::{
                seal::{DigestSeal, EventSeal, Seal},
                threshold::SignatureThreshold,
            },
            KeyEvent,
        },
        event_message::{
            event_msg_builder::EventMsgBuilder, msg::KeriEvent, signed_event_message::Notice,
            EventTypeTag,
        },
        prefix::{BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
        signer::Signer,
    };
    use said::SelfAddressingIdentifier;
    use tempfile::NamedTempFile;

    use super::{verify, AcdcBinding, Binding};
    use crate::registry::{
        event::datetime, Blinding, RegistryError, RegistryIlk, RegistryMessage, Salt, StateBlock,
    };

    /// An Issuer with a KEL in which it anchors registry events.
    pub(crate) struct Issuer {
        _path: NamedTempFile,
        processor: BasicProcessor<RedbDatabase>,
        pub(crate) storage: EventStorage<RedbDatabase>,
        signer: Signer,
        next: Signer,
        pub(crate) id: IdentifierPrefix,
        last: SelfAddressingIdentifier,
        sn: u64,
    }

    impl Issuer {
        pub(crate) fn new() -> Self {
            let path = NamedTempFile::new().unwrap();
            let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
            let (signer, next) = (Signer::new(), Signer::new());
            let icp = EventMsgBuilder::new(EventTypeTag::Icp)
                .with_keys(vec![BasicPrefix::Ed25519(signer.public_key())])
                .with_threshold(&SignatureThreshold::Simple(1))
                .with_next_keys(vec![BasicPrefix::Ed25519(next.public_key())])
                .build()
                .unwrap();
            let issuer = Issuer {
                _path: path,
                processor: BasicProcessor::new(db.clone(), None),
                storage: EventStorage::new(db),
                signer,
                next,
                id: icp.data.get_prefix(),
                last: icp.digest().unwrap(),
                sn: 0,
            };
            issuer.accept(&icp);
            issuer
        }

        fn accept(&self, event: &KeriEvent<KeyEvent>) {
            let sig = SelfSigningPrefix::Ed25519Sha512(
                self.signer.sign(event.encode().unwrap()).unwrap(),
            );
            let notice = Notice::Event(event.sign(
                vec![IndexedSignature::new_both_same(sig, 0)],
                None,
                None,
            ));
            self.processor.process_notice(&notice).unwrap();
        }

        /// Anchors `seals` in an interaction event.
        pub(crate) fn anchor(&mut self, seals: Vec<Seal>) {
            self.sn += 1;
            let ixn = EventMsgBuilder::new(EventTypeTag::Ixn)
                .with_prefix(&self.id)
                .with_sn(self.sn)
                .with_previous_event(&self.last)
                .with_seal(seals)
                .build()
                .unwrap();
            self.accept(&ixn);
            self.last = ixn.digest().unwrap();
        }

        /// The Issuer's signature on `data`, bound to its latest
        /// establishment event, as an exchange carries it.
        pub(crate) fn sign(
            &self,
            data: &[u8],
        ) -> keri_core::event_message::signature::Signature {
            use keri_core::event_message::signature::{Signature, SignerData};
            let seal = self
                .storage
                .get_last_establishment_event_seal(&self.id)
                .unwrap();
            let sig = SelfSigningPrefix::Ed25519Sha512(self.signer.sign(data).unwrap());
            Signature::Transferable(
                SignerData::EventSeal(seal),
                vec![IndexedSignature::new_both_same(sig, 0)],
            )
        }

        /// The Issuer's KEL as a CESR stream.
        pub(crate) fn kel(&self) -> Vec<u8> {
            use keri_core::event_message::signed_event_message::Message;
            self.storage
                .get_kel_messages_with_receipts_all(&self.id)
                .unwrap()
                .unwrap()
                .into_iter()
                .flat_map(|notice| Message::Notice(notice).to_cesr().unwrap())
                .collect()
        }

        /// Abandons the identifier: a rotation to the revealed next key,
        /// committing to no next keys.
        pub(crate) fn abandon(&mut self) {
            self.sn += 1;
            let rot = EventMsgBuilder::new(EventTypeTag::Rot)
                .with_prefix(&self.id)
                .with_sn(self.sn)
                .with_previous_event(&self.last)
                .with_keys(vec![BasicPrefix::Ed25519(self.next.public_key())])
                .with_threshold(&SignatureThreshold::Simple(1))
                .with_next_keys(vec![])
                .with_next_threshold(&SignatureThreshold::Simple(0))
                .build()
                .unwrap();
            self.signer = std::mem::replace(&mut self.next, Signer::new());
            self.accept(&rot);
            self.last = rot.digest().unwrap();
        }

        /// Anchors `event` as keripy does: an event seal naming the
        /// registry and the position.
        fn anchor_event(&mut self, event: &RegistryMessage) {
            let seal = EventSeal::new(
                IdentifierPrefix::SelfAddressing(event.registry().unwrap().into()),
                event.sn(),
                event.said().unwrap(),
            );
            self.anchor(vec![Seal::Event(seal)]);
        }
    }

    fn day(n: i64) -> chrono::DateTime<chrono::FixedOffset> {
        (Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + Duration::days(n)).into()
    }

    fn inception(issuer: &Issuer) -> RegistryMessage {
        RegistryMessage::incept(&issuer.id, "0ABrZXJpc3BlY3dvcmtyYXcw", &datetime(&day(0))).unwrap()
    }

    fn bup(prior: &RegistryMessage, block: &StateBlock) -> RegistryMessage {
        let timestamp = datetime(&day(prior.sn() as i64 + 1));
        RegistryMessage::blindable_update(prior, &block.blid().unwrap(), &timestamp).unwrap()
    }

    fn private() -> Blinding {
        Blinding::Private(Salt::new(*b"0123456789abcdef"))
    }

    fn acdc() -> SelfAddressingIdentifier {
        "EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur"
            .parse()
            .unwrap()
    }

    /// A registry in which `acdc()` is issued and then revoked.
    struct Registry {
        issuer: Issuer,
        rip: RegistryMessage,
        updates: Vec<RegistryMessage>,
        blocks: Vec<StateBlock>,
    }

    fn issued_then_revoked() -> Registry {
        let mut issuer = Issuer::new();
        let blinding = private();
        let rip = inception(&issuer);
        issuer.anchor_event(&rip);
        let mut updates: Vec<RegistryMessage> = vec![];
        let mut blocks = vec![];
        for (n, state) in [(1, "issued"), (2, "revoked")] {
            let block = StateBlock::new(&blinding, n, Some(&acdc()), state).unwrap();
            let update = bup(updates.last().unwrap_or(&rip), &block);
            issuer.anchor_event(&update);
            updates.push(update);
            blocks.push(block);
        }
        Registry {
            issuer,
            rip,
            updates,
            blocks,
        }
    }

    fn binding(registry: &Registry, named: bool) -> AcdcBinding {
        AcdcBinding {
            said: acdc(),
            issuer: registry.issuer.id.clone(),
            registry: named.then(|| registry.rip.said().unwrap()),
        }
    }

    /// The whole chain, its disclosed head block and the ACDC naming the
    /// registry verify to the revoked state, in any order of updates.
    #[test]
    fn a_disclosed_registry_verifies_to_its_head_state() {
        let registry = issued_then_revoked();
        let mut updates = registry.updates.clone();
        updates.reverse();
        let state = verify(
            &registry.issuer.storage,
            &registry.rip,
            &updates,
            Some(&registry.blocks[1]),
            Some(&binding(&registry, true)),
        )
        .unwrap();
        assert_eq!(state.registry, registry.rip.said().unwrap());
        assert_eq!(state.issuer, registry.issuer.id);
        assert_eq!(state.head, registry.updates[1].said().unwrap());
        assert_eq!(state.sn, 2);
        assert_eq!(state.ilk, RegistryIlk::Bup);
        assert_eq!(state.acdc, Some(acdc()));
        assert_eq!(state.state.as_deref(), Some("revoked"));
        assert_eq!(state.timestamp, day(2));
        assert_eq!(state.binding, Some(Binding::Mutual));
        let anchoring: Vec<u64> = state.anchors.iter().map(|(sn, _)| *sn).collect();
        assert_eq!(anchoring, vec![1, 2, 3]);
    }

    /// Without a block the blinded head says nothing of its state; an ACDC
    /// that names no registry binds one way.
    #[test]
    fn a_blinded_head_hides_its_state() {
        let registry = issued_then_revoked();
        let state = verify(
            &registry.issuer.storage,
            &registry.rip,
            &registry.updates,
            None,
            None,
        )
        .unwrap();
        assert_eq!((state.acdc, state.state), (None, None));

        let state = verify(
            &registry.issuer.storage,
            &registry.rip,
            &registry.updates,
            Some(&registry.blocks[1]),
            Some(&binding(&registry, false)),
        )
        .unwrap();
        assert_eq!(state.binding, Some(Binding::OneWay));
    }

    /// An event the Issuer did not anchor is not part of the registry yet.
    #[test]
    fn an_unanchored_update_is_missing_its_anchor() {
        let mut registry = issued_then_revoked();
        let block = StateBlock::new(&private(), 3, Some(&acdc()), "issued").unwrap();
        let unanchored = bup(&registry.updates[1], &block);
        registry.updates.push(unanchored.clone());
        assert_eq!(
            verify(
                &registry.issuer.storage,
                &registry.rip,
                &registry.updates,
                None,
                None
            ),
            Err(RegistryError::MissingAnchor(unanchored.said().unwrap()))
        );
    }

    /// Withholding the revocation is caught: the Issuer's KEL names a later
    /// position of the registry.
    #[test]
    fn a_withheld_update_makes_the_registry_stale() {
        let registry = issued_then_revoked();
        let result = verify(
            &registry.issuer.storage,
            &registry.rip,
            &registry.updates[..1],
            Some(&registry.blocks[0]),
            Some(&binding(&registry, true)),
        );
        assert!(matches!(result, Err(RegistryError::Stale(_))), "{result:?}");
    }

    /// Registries anchored by digest seals alone verify too, though a
    /// withheld update then goes unnoticed: the seals name no position.
    #[test]
    fn digest_anchors_prove_commitment_only() {
        let mut issuer = Issuer::new();
        let rip = inception(&issuer);
        let blocks: Vec<StateBlock> = ["issued", "revoked"]
            .iter()
            .map(|state| StateBlock::new(&Blinding::Public, 1, Some(&acdc()), state).unwrap())
            .collect();
        let first = bup(&rip, &blocks[0]);
        let second = bup(&first, &blocks[1]);
        for event in [&rip, &first, &second] {
            issuer.anchor(vec![Seal::Digest(DigestSeal::new(event.said().unwrap()))]);
        }
        let state = verify(&issuer.storage, &rip, &[first], Some(&blocks[0]), None).unwrap();
        assert_eq!(state.state.as_deref(), Some("issued"));
    }

    /// Two anchored updates at one position are duplicity, whichever is
    /// presented first.
    #[test]
    fn two_anchored_updates_at_one_position_are_duplicity() {
        let mut registry = issued_then_revoked();
        let other = StateBlock::new(&Blinding::Public, 1, Some(&acdc()), "issued").unwrap();
        let fork = bup(&registry.updates[0], &other);
        registry.issuer.anchor_event(&fork);
        let result = verify(
            &registry.issuer.storage,
            &registry.rip,
            &[
                registry.updates[0].clone(),
                fork,
                registry.updates[1].clone(),
            ],
            None,
            None,
        );
        assert!(
            matches!(result, Err(RegistryError::Duplicity(_))),
            "{result:?}"
        );
    }

    /// Updates must run from the inception, each after the one before.
    #[test]
    fn a_broken_chain_is_refused() {
        let registry = issued_then_revoked();
        let storage = &registry.issuer.storage;
        let gap = verify(storage, &registry.rip, &registry.updates[1..], None, None);
        assert!(matches!(gap, Err(RegistryError::Chain(_))), "{gap:?}");

        let other = Issuer::new();
        let foreign = bup(&inception(&other), &registry.blocks[0]);
        let result = verify(storage, &registry.rip, &[foreign], None, None);
        assert!(matches!(result, Err(RegistryError::Chain(_))), "{result:?}");

        let result = verify(storage, &registry.updates[0], &[], None, None);
        assert!(matches!(result, Err(RegistryError::Chain(_))), "{result:?}");
    }

    /// The disclosed block must be the head's, and an ACDC shown against a
    /// blinded head needs it.
    #[test]
    fn the_head_block_must_be_disclosed_and_match() {
        let registry = issued_then_revoked();
        let storage = &registry.issuer.storage;
        let acdc = binding(&registry, true);
        for block in [None, Some(&registry.blocks[0])] {
            let result = verify(
                storage,
                &registry.rip,
                &registry.updates,
                block,
                Some(&acdc),
            );
            assert!(matches!(result, Err(RegistryError::Blind(_))), "{result:?}");
        }
        let forged = StateBlock::new(&private(), 2, Some(&super::tests::acdc()), "issued").unwrap();
        let result = verify(
            storage,
            &registry.rip,
            &registry.updates,
            Some(&forged),
            None,
        );
        assert!(matches!(result, Err(RegistryError::Blind(_))), "{result:?}");
    }

    /// The ACDC must be the one the head names, from the registry's Issuer,
    /// and name no other registry.
    #[test]
    fn the_acdc_must_bind_to_the_registry() {
        let registry = issued_then_revoked();
        let storage = &registry.issuer.storage;
        let block = Some(&registry.blocks[1]);
        let mut others = vec![];
        let mut acdc = binding(&registry, true);
        acdc.said = registry.rip.said().unwrap();
        others.push(acdc);
        let mut acdc = binding(&registry, true);
        acdc.issuer = Issuer::new().id;
        others.push(acdc);
        let mut acdc = binding(&registry, true);
        acdc.registry = Some(registry.updates[0].said().unwrap());
        others.push(acdc);
        for acdc in others {
            let result = verify(
                storage,
                &registry.rip,
                &registry.updates,
                block,
                Some(&acdc),
            );
            assert!(
                matches!(result, Err(RegistryError::Binding(_))),
                "{result:?}"
            );
        }
    }

    /// An `upd` discloses its state itself.
    #[test]
    fn an_update_discloses_its_state() {
        let mut issuer = Issuer::new();
        let rip = inception(&issuer);
        issuer.anchor_event(&rip);
        let upd = RegistryMessage::update(&rip, &acdc(), "issued", &datetime(&day(1))).unwrap();
        issuer.anchor_event(&upd);
        let presented = AcdcBinding {
            said: acdc(),
            issuer: issuer.id.clone(),
            registry: Some(rip.said().unwrap()),
        };
        let state = verify(&issuer.storage, &rip, &[upd], None, Some(&presented)).unwrap();
        assert_eq!(state.ilk, RegistryIlk::Upd);
        assert_eq!(state.state.as_deref(), Some("issued"));
        assert_eq!(state.binding, Some(Binding::Mutual));
    }
}
