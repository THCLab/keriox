# State storage gaps: what still lives in files

`StorageConfig` (Redb | InMemory, Postgres planned) governs the **event
databases**: KEL, TEL, OOBI storage, escrows and the mailbox query cache.
Everything else the SDK persists is still plain files under the store root.
This document inventories that state, where each piece *should* live, and
what blocks `InMemory`/`Postgres` deployments from being fully
filesystem-free.

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

**Target:** a `SecretsStore` trait with the current file layout as the
default implementation, so platforms can plug the OS keychain (Android
Keystore/StrongBox, iOS Keychain, Secret Service on Linux) for
software-managed seeds. Seeds must not move into the event database under
any backend — a Postgres deployment must not become a remote plaintext key
store, and an in-memory deployment of *events* does not imply the keys are
disposable. With keyprovider in use, Category A is already empty; the gap
only concerns the software-key path.

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

**Target:** one store-level metadata database (a `meta` redb created
through the same `StorageConfig`, so it is automatically in-memory or — 
later — Postgres-backed) with tables `aliases(alias → id, reg_id,
delegated_id, delegator_id)`, `groups(alias → group_id, member_alias,
participants)`, `credentials(alias → [credential_id])`,
`contacts(aid → source)`. `KeriStore`'s `read_file`/`write_file` helpers
are already the single choke point, so the migration is mechanical;
keep a one-time importer for existing file-layout stores
(dkms-bin compatibility).

### Category C — structural inefficiencies

| Item | Today | Issue |
|---|---|---|
| one event database **per alias** (`<alias>/db`) | each alias opens its own KEL/TEL/escrow set | N aliases = N redb files and N controller stacks; contacts make it worse |
| one database **per contact** (`.contacts/<aid>/db`) | full controller stack per imported contact | importing 50 contacts opens 50 redb databases |
| mailbox query cache (`<alias>/db/query_cache`) | separate redb per alias | covered by `StorageConfig` already, listed for completeness |

**Target:** a single store-level event database shared by all aliases and
contacts. The underlying `KnownEvents`/`RedbDatabase` are already
multi-identifier (they key everything by identifier prefix — the witness
runs exactly one database for thousands of AIDs). The per-alias split
exists for historical dkms-bin compatibility, not by design. Collapsing it
also shrinks the embedding/lock surface to a single redb file and makes
`Keri::verify`'s scan-all-aliases loop a single-database lookup.

## Deployment matrix (after closing the gaps)

| Deployment | Events | Metadata | Keys |
|---|---|---|---|
| desktop/server file-backed | redb files | meta db (redb) | SecretsStore: file (default) or OS keychain |
| tests / ephemeral agents | `InMemory` | meta db (in-memory) | in-memory seeds — **zero filesystem use** |
| Android / iOS | redb files in app dir | meta db | **HSM via keyprovider — zero key bytes stored** |
| server-side Postgres (planned) | Postgres | same Postgres | KMS/HSM via keyprovider |

## Suggested order of work

1. **Store-level `meta` database** (Category B) — removes the filesystem
   requirement from `InMemory`, unblocks a diskless Postgres mode later,
   and is purely mechanical behind `read_file`/`write_file`.
2. **`SecretsStore` trait** (Category A) — default file impl preserves
   today's behavior; keychain impls land per platform. Keyprovider users
   are unaffected.
3. **Single shared event database** (Category C) — biggest structural win,
   touches `KeriStore`'s controller cache and the facade's verify loop;
   do last, after 1 makes alias enumeration db-backed.
4. **`StorageConfig::Postgres`** — now only requires the enum-dispatch work
   in `advanced::Controller`/`Identifier`, since no state remains
   filesystem-bound.
