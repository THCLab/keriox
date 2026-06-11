# KERI concepts for non-KERI developers

You can use `keri-sdk` without reading this. But when a doc comment mentions
a *witness* or an *OOBI URL*, this page tells you what that means — in plain
language, no protocol spec required.

## Identity / identifier (AID)

A username that proves itself. The identifier string (e.g.
`EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5`) is derived from the
identity's own first keys, so nobody can claim it without those keys — no
registration authority needed. In the SDK it's the [`IdentityId`] you get
from `identity.id()`; share it freely, it is public.

## Key event log (KEL)

An append-only changelog of an identity's keys: which key it started with,
every rotation since, and what it has anchored (credentials, delegations).
Each entry is signed and chains to the previous one, so the whole history is
tamper-evident. Verifying a signature means checking it against this log —
that's why you import a contact before verifying them.

## Key rotation & pre-rotation

Scheduled key replacement with a twist: every key event also **commits to
the digest of the next key**. To rotate, you reveal the key you committed to
earlier and commit to a new next one. The consequence: stealing your
*current* key is not enough to take over your identity — the attacker would
also need the next key, which has never been used or transmitted. Old
signatures stay verifiable because the log proves which key was valid when.
In the SDK this is one call: `identity.rotate()`.

## Witness

A server that countersigns your key events and serves your key history to
others — your identity's always-online publisher. You choose your witnesses
(their URLs go into `new_identity(...).witness(url)`), you can replace them,
and they cannot forge anything: they only receipt what you signed. Multiple
witnesses with a threshold protect against a compromised one.

## Watcher

The mirror image of a witness: a server that fetches and tracks *other
people's* key histories on your behalf, so you don't have to trust a single
source. Optional for simple setups.

## OOBI ("out-of-band introduction")

A URL where an identifier's key history can be fetched, e.g.
`http://witness.example/oobi/EJe6f…/witness/BNzwA…`. It's how identities
find each other: Alice sends Bob her OOBI URL over any channel (email, QR
code); Bob's SDK fetches her history from it (`keri.import_contact(url)`).
The URL itself carries no secrets — the fetched history is self-verifying.

## Credential, registry (TEL)

A credential here is any document whose digest the issuer anchors in their
**registry** — a public issued/revoked switchboard (the spec calls it a
Transaction Event Log). Verifiers check the registry to see whether the
credential is still valid; revocation is one call by the issuer and visible
to everyone. The SDK creates the registry automatically on first
`identity.issue(...)`.

## Delegation

One identity authorizing another to act under its authority — e.g. your
phone's identity delegated by your main identity. The delegation is anchored
in the delegator's key log, so verifiers can walk the chain of authority.
Inherently a two-party handshake: request → approve → finalize
(`delegated_by` → `pending_requests` → `finalize`).

## Group identity (multisig)

One identity controlled by several members with a signing threshold ("2 of
3 directors"). Group events are co-signed by members through their shared
witness's mailbox. In the SDK: `identity.new_group(...)`, invitations arrive
via `pending_requests()`.

## SAID & CESR (you'll see these in strings)

A **SAID** is a self-addressing identifier: the digest of a document
embedded inside the document itself (the `d` field), making it
tamper-evident. **CESR** is the text encoding KERI uses for events, keys and
signatures — the reason a signed message is one copy-pasteable string. The
SDK produces and parses both; you only ever handle strings.

[`IdentityId`]: https://docs.rs/keri-sdk
