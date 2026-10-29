//! Messages between identities. Multi-party flows (group events, delegation
//! requests and approvals) produce messages for the other parties, which
//! the application delivers through any channel, such as a messagebox; the
//! recipient takes each one with [`crate::Identity::receive`].

use keri_controller::{BasicPrefix, IdentifierPrefix};

use crate::advanced::Forward;
use crate::error::Result;
use crate::ids::IdentityId;
use crate::keri::KeriInner;

/// A message to deliver to another identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    /// Who it is for: an identity, or for a delegation approval the
    /// delegated identity, whose requester takes it.
    pub to: IdentityId,
    /// The message, as CESR.
    pub message: Vec<u8>,
}

/// The identities this store knows (its own and its contacts) whose current
/// key is among `keys`: the members of a group whose event names `keys`.
pub(crate) fn members_by_keys(
    keri: &KeriInner,
    member_alias: &str,
    keys: &[BasicPrefix],
) -> Result<Vec<IdentifierPrefix>> {
    let member = keri.store.load(member_alias)?;
    let mut members = vec![];
    for alias in keri.all_kel_aliases() {
        let Ok(known) = keri.store.load(&alias) else {
            continue;
        };
        let id = known.id().clone();
        if members.contains(&id) {
            continue;
        }
        let _ = keri.copy_kel_into(member_alias, &id);
        let current = member
            .find_state(&id)
            .map(|state| state.current.public_keys)
            .unwrap_or_default();
        if current.iter().any(|key| keys.contains(key)) {
            members.push(id);
        }
    }
    Ok(members)
}

/// The messages to deliver for `forwards`, each to whom it names.
pub(crate) fn direct(forwards: Vec<Forward>) -> Vec<Outgoing> {
    forwards
        .into_iter()
        .map(|forward| Outgoing {
            to: IdentityId::from(forward.to),
            message: forward.message,
        })
        .collect()
}

/// The messages to deliver for `forwards`: a forward for `group` goes to
/// each of its `members` other than `own`, any other to whom it names.
pub(crate) fn outgoing(
    forwards: Vec<Forward>,
    group: Option<&IdentifierPrefix>,
    members: &[IdentifierPrefix],
    own: &IdentifierPrefix,
) -> Vec<Outgoing> {
    let mut out = vec![];
    for forward in forwards {
        if Some(&forward.to) == group {
            out.extend(
                members
                    .iter()
                    .filter(|member| *member != own)
                    .map(|member| Outgoing {
                        to: IdentityId::from(member.clone()),
                        message: forward.message.clone(),
                    }),
            );
        } else {
            out.push(Outgoing {
                to: IdentityId::from(forward.to),
                message: forward.message,
            });
        }
    }
    out
}
