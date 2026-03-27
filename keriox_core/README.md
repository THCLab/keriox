# keriox_core

Implementation of the core features of [KERI (Key Event Receipt Infrastructure)](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html). It includes KERI events and their processing logic.

The `actor` module provides higher-level functions for generating, parsing, and processing KERI events. However, if you need even more advanced elements that enable you to work with encoded events directly, you can explore the [`components/controller`](https://github.com/THCLab/keriox/tree/master/components/controller) workspace.

## Example

To use this library, a third-party key provider that derives public-private key pairs is required. For testing purposes, the `CryptoBox` from the `signer` module can be used. It provides signing helpers. To see some examples, please refer to the [`keriox_core/tests`](https://github.com/THCLab/keriox/tree/master/keriox_core/tests) folder.

## Available Features

- `storage-redb` *(default)*: enables [redb](https://github.com/cberner/redb) as the persistent storage backend. Without this feature, an in-memory `MemoryDatabase` is available for testing or plugging in custom backends.
- `query`: enables query messages and their processing logic.
- `oobi`: provides events and logic for the [oobi discovery mechanism](https://weboftrust.github.io/ietf-oobi/draft-ssmith-oobi.html).
- `oobi-manager`: high-level OOBI management. Implies `oobi`, `query`, and `storage-redb`.
- `mailbox`: enables the storing of messages intended for other identifiers and provides them to recipients later. This feature is meant for witnesses and watchers. Implies `query` and `storage-redb`.

## Architecture

### NotificationBus

`NotificationBus` is a pluggable dispatch abstraction for event notifications. The default implementation dispatches in-process, but custom implementations (e.g. SQS for serverless environments) can be injected:

```rust
// Use the default in-process dispatch:
let bus = NotificationBus::new();

// Or provide a custom dispatch:
let bus = NotificationBus::from_dispatch(my_custom_dispatch);
```

You can also pass an existing bus to `default_escrow_bus` via `Some(bus)` to share a single dispatch across escrows.

### EscrowSet

`EscrowSet<D>` is a named struct (replacing the previous anonymous tuple) returned by `default_escrow_bus`. It provides typed access to each escrow:

- `out_of_order` -- events received before their dependencies
- `partially_signed` -- events awaiting additional signatures
- `partially_witnessed` -- events awaiting additional witness receipts
- `delegation` -- delegated events awaiting approval
- `duplicitous` -- detected duplicitous events

