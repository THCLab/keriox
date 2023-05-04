# keriox_core

Implementation of the core features of [KERI (Key Event Receipt Infrastructure)](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html). It includes KERI events and their processing logic.

The `actor` module provides higher-level functions for generating, parsing, and processing KERI events. However, if you need even more advanced elements that enable you to work with encoded events directly, you can explore the [`components/controller`](https://github.com/THCLab/keriox/tree/master/components/controller) workspace.

## Example

To use this library, a third-party key provider that derives public-private key pairs is required. For testing purposes, the `CryptoBox` from the `signer` module can be used. It provides signing helpers. To see some examples, please refer to the [`keriox_core/tests`](https://github.com/THCLab/keriox/tree/master/keriox_core/tests) folder.

## Available Features

- `query`: enables query messages and their processing logic.
- `oobi`: provides events and logic for the [oobi discovery mechanism](https://weboftrust.github.io/ietf-oobi/draft-ssmith-oobi.html).
- `mailbox`: enables the storing of messages intended for other identifiers and provide them to recipient later. This feature is meant for witnesses and watchers.

