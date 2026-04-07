# keriox_sdk

High-level SDK for KERI and TEL operations, providing composable building blocks for both traditional and serverless deployments.

## Key Types

- **`KeriRuntime<D>`**: The shared KERI processing stack -- bundles `BasicProcessor`, `EventStorage`, `EscrowSet`, and `NotificationBus`. Use `KeriRuntime::new(db)` for defaults or `KeriRuntime::with_config(db, config, Some(bus))` to inject a custom notification bus (e.g. SQS-backed dispatch for Lambda handlers).
- **`Controller<D, T>`**: Composes `KeriRuntime<D>` with a TEL layer (`Tel<T, D>`). Provides methods for inception, KEL/TEL processing, and state queries. Access the KERI runtime via the public `kel` field.
- **`Identifier<D>`**: Manages a specific identifier's Key Event Log, including event generation and state retrieval.

## Usage

```rust
use keri_sdk::{Controller, KeriRuntime};

// Standalone KERI runtime (no TEL)
let runtime = KeriRuntime::new(event_db.clone());
runtime.processor.process_notice(&notice)?;

// Full Controller with TEL
let controller = Controller::new(event_db, tel_db);
```

## Re-exports

This crate re-exports commonly used types from `keri-core` and `teliox`:
- `database` module and `Signer` from keri-core
- `TelEventDatabase` and `TelEventStorage` from teliox
