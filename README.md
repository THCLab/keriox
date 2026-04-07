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
