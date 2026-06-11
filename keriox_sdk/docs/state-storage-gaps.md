# State storage: design and remaining gaps

`StorageConfig` (Redb | InMemory, Postgres planned) governs the **event
databases**: KEL, TEL, OOBI storage, escrows and the mailbox query cache.
This document inventories every other piece of SDK state, where it lives,
and what remains before a `Postgres` deployment is fully filesystem-free.

> **Status:** categories A–C below are implemented. Alias metadata lives in
> the store-level `meta` database (legacy file layouts are detected and
> migrated on read), seeds go through the pluggable `SecretsStore`, and new
> stores share a single event database. The remaining gap is the
> `StorageConfig::Postgres` variant (step 4).

The guiding assumption for key material is the mobile/HSM deployment
(Android Keystore via the `keyprovider` feature): **private keys are not the
SDK's to store**. The storage design must hold with zero key bytes on disk.

## Inventory

### Category A — key material (must never enter the event database)

| File | Contents | With HSM/keyprovider | Gap |
|---|---|---|---|
| `<alias>/priv_key` | current signing seed, **plaintext** | *file does not exist* — the provider holds the key | software-key fallback writes plaintext seeds to disk; no pluggable secrets backend |
| `<alias>/next_priv_key` | pre-rotation seed, **plaintext** | *does not exist* | same |

`IdentityBackup` (export/restore) also carries both seeds in serialized
form; HSM-backed identities already refuse export.

**Implemented:** `advanced::secrets::SecretsStore` with
`FileSecretsStore` as the default (today's layout, full compatibility) and
`MemorySecretsStore` for ephemeral stores;
`KeriStore::open_with_options(root, storage, secrets)` plugs a custom
backend. Platform keychain implementations (Android Keystore/StrongBox,
iOS Keychain, Secret Service) are per-platform follow-ups. Seeds never
enter the event or metadata databases under any backend. With keyprovider
in use, Category A is empty — no key bytes are stored at all.

### Category B — alias metadata (non-secret bookkeeping; should move into a db)

| File | Contents | Written by |
|---|---|---|
| `<alias>/id` | identifier prefix (CESR text) | create / restore / delegation finalize |
| `<alias>/reg_id` | TEL registry id | first credential issuance |
| `<alias>/delegated_id` | delegated AID awaiting approval | delegation request |
| `<alias>/delegator_id` | delegator AID | delegation request |
| `<alias>/group_id` | group AID | group create / join |
| `<alias>/member_alias` | back-reference to the member alias | group create / join |
| `<alias>/participants` | member AIDs, JSON, **in inception key order** | group create / rotate |
| `<alias>/credentials` | issued credential ids, line-per-entry | facade issuance |
| `.contacts/<aid>/id` | contact's AID | contact import |
| `.contacts/<aid>/source` | witness base URL for refresh | contact import |

None of this is secret and all of it is small, but it is the reason
`StorageConfig::InMemory` still needs a directory and a future
`Postgres` mode would still touch the local filesystem.

**Implemented:** one store-level metadata database (`<root>/meta`, created
through the same `StorageConfig`, so it is automatically in-memory when the
events are) holding `(alias, field) → value` for all of the above,
including the facade's credential indexes and contact sources
(`KeriStore::{read_meta, write_meta}`). Values written by older SDK
versions as one file per field are found via fallback and migrated into
the database on first read — dkms-bin stores keep working with no
migration step.

### Category C — structural inefficiencies

| Item | Today | Issue |
|---|---|---|
| one event database **per alias** (`<alias>/db`) | each alias opens its own KEL/TEL/escrow set | N aliases = N redb files and N controller stacks; contacts make it worse |
| one database **per contact** (`.contacts/<aid>/db`) | full controller stack per imported contact | importing 50 contacts opens 50 redb databases |
| mailbox query cache (`<alias>/db/query_cache`) | separate redb per alias | covered by `StorageConfig` already, listed for completeness |

**Implemented:** new stores share a single event database (`<root>/db`)
across all aliases and contacts; stores that already have per-alias
databases are detected and keep their layout permanently (the decision is
persisted in the metadata database). Landing this exposed an upstream bug:
the controller's mailbox query cache and published-receipt cache were
keyed by witness only, so identifiers sharing one database consumed each
other's mailbox read positions — both caches are now keyed by
(identifier, witness).

## Deployment matrix (after closing the gaps)

| Deployment | Events | Metadata | Keys |
|---|---|---|---|
| desktop/server file-backed | redb files | meta db (redb) | SecretsStore: file (default) or OS keychain |
| tests / ephemeral agents | `InMemory` | meta db (in-memory) | in-memory seeds — **zero filesystem use** |
| Android / iOS | redb files in app dir | meta db | **HSM via keyprovider — zero key bytes stored** |
| server-side Postgres (planned) | Postgres | same Postgres | KMS/HSM via keyprovider |

## Remaining work

1. **Platform keychain `SecretsStore` implementations** — Android
   Keystore/StrongBox, iOS Keychain, Secret Service; land with the
   respective bindings.
2. **`StorageConfig::Postgres`** — only requires the enum-dispatch work in
   `advanced::Controller`/`Identifier` (RedbIdentifier | PostgresIdentifier)
   plus async construction; no SDK state remains filesystem-bound besides
   the default file secrets store.
