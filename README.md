# KERIOX

## Introduction

KERIOX is an open source Rust implementation of the [ Key Event Receipt Infrastructure (KERI) ](https://github.com/decentralized-identity/keri), a system designed to provide a secure identifier-based trust spanning layer for any stack. [The current version of the KERI paper can be found here](https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/KERI_WP_2.x.web.pdf).

KERI provides the same security and verifiability properties for transactions as a blockchain or distributed ledger can, without the overhead of requiring an absolute global ordering of transactions. Because of this, there is no need for a cannonical chain and thus there is no "KERI Chain" or "KERI Network". KERI Identifiers can be generated independantly in a self-sovereign and privacy-preserving manner and are secured via a self-certifying post-quantum resistant key management scheme based on blinded pre-rotation, auditable and flexible key events and a distributed conflict resolution algorithm called KAACE.

## License

EUPL 1.2 

We have distilled the most crucial license specifics to make your adoption seamless: [see here for details](https://github.com/THCLab/licensing).

## Organization

This repository provides implementation of KERI. It contains:
* High level interface for [Witness](./components/witness)
* High level interface for [Watcher](./components/watcher)
* High level interface for [Controller](./keriox_core/src/controller)

For ready to use client libraries, we encourage to visit https://github.com/THCLab/keri-bindings that provide bindings to other languages via FFI layer. 

For ready to use infrastructure components, see our prebaked Docker images:
* [Witness](https://hub.docker.com/r/humancolossus/keriox-witness)
* [Watcher](https://hub.docker.com/r/humancolossus/keriox-watcher)


## Example

See this [repo](https://github.com/THCLab/dkms-demo) that demonstrates the DKMS components usage along with sample apps.
