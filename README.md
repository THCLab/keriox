# KERIOX

## What is KERIOX in a nutshell?

KERIOX is a **Rust** implementation of the [Decentralized Key Management System (DKMS)](https://dkms.colossi.network/) that under the hood uses the [Key Event Receipt Infrastructure (KERI)](https://trustoverip.github.io/tswg-keri-specification/) protocol. 

The [Human Colossus Foundation](https://humancolossus.foundation/) has been developing and maintaining KERIOX since 2020.

## Usage

- For running example infrastructure (Witnesses, etc.), see https://github.com/THCLab/ambient-infrastructure
- Connect to the Infrastructure
  - for Command-Line Interface (CLI)-based interaction, use [`dkms-bin`](https://github.com/THCLab/dkms-bin) 
  - for Rust client, see [test](https://github.com/THCLab/keriox/blob/master/keriox_tests/tests/indirect_mode_signing.rs).
  - for FFI bindings (clients for different programming languages), see https://github.com/THCLab/keri-bindings

## Introduction

KERIOX is an open-source Rust implementation of the [ Key Event Receipt Infrastructure (KERI) ](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html), a system designed to provide a secure identifier-based trust spanning layer for any stack. [The current version of the KERI paper can be found here](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

KERI provides the same security and verifiability properties for transactions as a blockchain or distributed ledger can, without the overhead of requiring an absolute global ordering of transactions. Because of this, there is no need for a canonical chain and thus there is no "KERI Chain" or "KERI Network". KERI Identifiers can be generated independently in a self-sovereign and privacy-preserving manner and are secured via a self-certifying post-quantum resistant key management scheme based on blinded pre-rotation, auditable and flexible key events and a distributed conflict resolution algorithm called KAACE.

## Architecture

KERIOX is designed around pluggable abstractions that allow it to run in diverse environments. The `EventDatabase` trait abstracts storage so that backends can be swapped at compile time; `redb` is the default (feature-flagged as `storage-redb`), and an in-memory implementation is available for testing or custom backends. Notification dispatch is also pluggable via `NotificationBus`, which supports injectable dispatch strategies suitable for serverless environments such as SQS-backed message routing. The `KeriRuntime<D>` struct bundles the processor, storage, escrows, and notification bus into a single composable unit, enabling thin Lambda handlers or other lightweight entry points.

## Abandoning an identifier

Following the [KERI specification](https://trustoverip.github.io/kswg-keri-specification/),
an identifier is abandoned by a rotation (`rot`, or `drt` for a delegated
identifier) that commits to no next keys (`n=[]`, `nt=0`); an inception that
does so makes it non-transferable instead. Either way its key event log is
final and no more key events are allowed in it:

- **Core** refuses every later event (`Error::AbandonedIdentifier` or
  `Error::NonTransferableIdentifier`). For an abandoned identifier it also
  refuses replies, exchanges and transferable receipts signed by it, an
  extension beyond the specification: abandoning signals that its controller
  no longer speaks for it. Queries are still answered, so the owner can
  collect receipts for the abandonment. A non-transferable identifier keeps
  speaking for itself.
- As the specification requires, an establishment event's key list `k` must
  not be empty, an integer threshold (`kt`, `nt`) may not need more keys than
  its list has, and a weighted one has exactly one weight per key (KERIpy only
  checks for at most one). So no next keys means `nt=0`. A key event without
  a single controller signature is dropped, not escrowed, and answered with
  `400`.
- **Witnesses** receipt the abandonment but answer `410 Gone` to anything
  after it.
- **Watchers** serve the final log, stop polling the witnesses for it, and
  answer full-log queries without waiting on them.
- Both serve `GET /identifiers/{aid}/state` without authentication: the
  identifier's sn, last event, witnesses, whether it is `transferable` and,
  when abandoned, `"abandoned": {"sn", "said"}`. It is a hint for operators and fresh
  clients; whoever relies on it verifies the KEL through an authenticated
  watcher query. Unknown identifiers get `404`.
- Both list `"features": ["abandonment"]` on `GET /info`. Check every
  witness and watcher before abandoning an identifier: an older one would
  still receipt or serve events that follow the abandonment.
- The **controller** builds the event (`Identifier::abandon`,
  `abandon_group`), and the **SDK** wraps it (`Identity::abandon`,
  `KeriStore::abandon`, `operations::abandon`, `Keri::remove_identity`).
  The SDK refuses to verify anything signed with an abandoned identifier's
  final keys.

## KERI 1.0 and 2.0

keriox reads KERI 1.0 and KERI 2.0 messages, and writes KERI 1.0 unless told
otherwise, so a node or client can be upgraded before its peers.

- KERI 2.0 key events, receipts, `qry`, `rpy` and `exn` are written with a
  2.0 version string and CESR 2.0 attachments. Routed messages (`qry`, `rpy`)
  name their sender in `i`, and `exn` carries `i`, `ri`, `x` and `p`; the
  sender must be the signer.
- What a node writes in answer to something follows what it answers: a
  receipt follows the event's version, a key state notice the query's.
- The **controller** writes its own messages in `ControllerConfig::keri_version`,
  the **SDK** in `KeriStore::with_keri_version`, and **witnesses** and
  **watchers** in `keri_version` in their configuration file (`1` or `2`;
  `WITNESS_KERI_VERSION` and `WATCHER_KERI_VERSION` in the environment).
- Switch a writer to 2.0 only once everything that reads its messages runs a
  keriox that reads 2.0. Older releases refuse KERI 2.0 messages.
- TEL events stay KERI 1.0: the KERI specification defines no TEL messages,
  and registries in KERI 2.0 come with ACDC 2.0.

## License

EUPL 1.2

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Status

KERIOX implementation is in progress and ongoing. We support all the KERI protocol's significant features and provide the second most advanced implementation right after the [keripy](https://github.com/weboftrust/keripy) reference implementation.

We furthermore support bindings to NodeJS and Dart. See our [keri-bindings](https://github.com/THCLab/keri-bindings) repository.

## Organization

This repository provides the implementation of the KERI protocol. [`keriox_core`](https://github.com/THCLab/keriox/tree/master/keriox_core) brings the core protocol features that are further consumed by the following concepts:

- [Witness](./components/witness): the KERI Witness
- [Watcher](./components/watcher): the KERI Watcher
- [Controller](./components/controller): the client for accessing the infrastructure
- [SDK](./keriox_sdk): high-level SDK providing `KeriRuntime` and `Controller` for KERI+TEL operations
- [Key Provider](./keri_keyprovider): pluggable cryptographic signing abstraction (software, file-encrypted, OS keychain, host-callback for mobile)

## Mobile support

KERIOX supports mobile targets (Android API 30+ and iOS) via:

- **`mobile` feature flag** on `keri-sdk` — enables `host` + `software` key providers, uses `rustls` for TLS
- **`HostCallbackKeyProvider`** in `keri_keyprovider` — delegates all signing to host platform callbacks (Android Keystore / iOS Keychain). Private keys never enter Rust memory.
- **`rustls`** TLS backend — pure Rust, no OpenSSL dependency
- **`redb`** storage — pure Rust, no mmap, works on both Android and iOS app sandboxes

See the [mobile SDK CI workflow](./.github/workflows/mobile.yml) for cross-compilation verification.
