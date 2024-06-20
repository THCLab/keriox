# KERIOX

## Usage

- Running infrastructure, see the following [example](https://github.com/THCLab/dkms-demo/tree/main/infrastructure).
- Running Controller (infrastructure client) see [test](https://github.com/THCLab/keriox/blob/master/keriox_tests/tests/indirect_mode_signing.rs).

## Introduction

KERIOX is an open source Rust implementation of the [ Key Event Receipt Infrastructure (KERI) ](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html), a system designed to provide a secure identifier-based trust spanning layer for any stack. [The current version of the KERI paper can be found here](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

KERI provides the same security and verifiability properties for transactions as a blockchain or distributed ledger can, without the overhead of requiring an absolute global ordering of transactions. Because of this, there is no need for a canonical chain and thus there is no "KERI Chain" or "KERI Network". KERI Identifiers can be generated independently in a self-sovereign and privacy-preserving manner and are secured via a self-certifying post-quantum resistant key management scheme based on blinded pre-rotation, auditable and flexible key events and a distributed conflict resolution algorithm called KAACE.

## License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Status

KERIOX implementation is in progress and ongoing. We support all the KERI protocol's significant features and provide the second most advanced implementation right after the [keripy](https://github.com/weboftrust/keripy) reference implementation.

We furthermore support bindings to NodeJS and Dart. See our [keri-bindings](https://github.com/THCLab/keri-bindings) repository.

## Organization

This repository provides implementation of KERI. Core protocol features are implemented in [`keriox_core`](https://github.com/THCLab/keriox/tree/master/keriox_core) workspace. Repository contains also workspaces for following KERI components:
* High level interface for [Witness](./components/witness)
* High level interface for [Watcher](./components/watcher)
* High level interface for [Controller](./components/controller)

For ready to use client libraries, we encourage to visit https://github.com/THCLab/keri-bindings that provide bindings to other languages via FFI layer. 

For ready to use infrastructure components, see our prebaked Docker images:
* [Witness](https://ghcr.io/thclab/keriox-witness)
* [Watcher](https://ghcr.io/thclab/keriox-watcher)
