# keri-sdk

Self-certifying digital identities with verifiable key rotation — no
blockchain, no central registry.

`keri-sdk` is the high-level Rust SDK for [KERI] (Key Event Receipt
Infrastructure). An identity created with it proves itself: its identifier is
derived from its own keys, every key rotation is recorded in a signed,
witness-receipted log, and anyone holding that log can verify your signatures
— including ones you made before rotating. You don't need to know any of the
protocol's internals to use this crate.

[KERI]: https://keri.one

## Quick start

```toml
[dependencies]
keri-sdk = { path = "../keriox_sdk" }
```

```rust,no_run
use keri_sdk::Keri;

#[tokio::main]
async fn main() -> keri_sdk::Result<()> {
    let keri = Keri::open("~/.myapp/keri")?;

    // Create an identity. The witness countersigns and publishes your key
    // history; pass its base URL and the SDK handles the rest.
    let alice = keri.new_identity("alice")
        .witness("http://witness.example:3232")
        .build().await?;

    // Sign — the result is a self-contained string: store it, send it.
    let signed = alice.sign(b"hello world").await?;

    // Verify — strictly offline, returns the payload and the proven signer.
    let verified = keri.verify(signed.as_cesr())?;
    assert_eq!(verified.payload, b"hello world");

    // Rotate keys. Old signatures stay verifiable; a stolen current key
    // can't hijack the identity (the next key was committed in advance).
    alice.rotate().await?;

    // Issue a revocable credential (the registry is created automatically).
    let diploma = alice.issue(br#"{"d":"","degree":"MSc"}"#).await?;
    assert!(keri.credential_status(&diploma.id).await?.is_valid());

    Ok(())
}
```

To verify someone **else's** signature, import them once — they share their
OOBI URL (`identity.oobi_url()`) or raw key history (`identity.kel()`):

```rust,ignore
keri.import_contact(&their_oobi_url).await?;
let verified = keri.verify(their_signed_message)?;
```

## What's in the box

| You want to… | Use |
|---|---|
| create / load identities | `Keri::open`, `Keri::new_identity`, `Keri::identity` |
| sign & verify | `Identity::sign`, `Keri::verify` |
| rotate keys | `Identity::rotate` |
| issue / revoke credentials, check status | `Identity::issue`, `Identity::revoke`, `Keri::credential_status` |
| verify strangers | `Identity::oobi_url` / `Identity::kel` + `Keri::import_contact` |
| device backup / recovery | `Identity::export`, `IdentityBuilder::restore_from` |
| delegate (phone acts under your main identity) | `IdentityBuilder::delegated_by`, `Identity::pending_requests` |
| group identities (multisig) | `Identity::new_group`, `Keri::group` |
| hardware keys (mobile keystore / HSM) | `IdentityBuilder::key_providers` (feature `keyprovider`) |
| anything lower-level | the [`advanced`](src/advanced/mod.rs) module |

## Learn more

- **[KERI concepts for non-KERI developers](docs/concepts.md)** — what a
  witness is, why rotation is safe, what an OOBI URL means; plain language,
  five minutes.
- **[Cookbook](docs/cookbook.md)** — "I want to X → call Y", including when
  to drop into `keri_sdk::advanced`.
- **End-to-end walkthroughs** — the `tests/e2e_*.rs` files are heavily
  narrated, runnable stories: identity lifecycle, credentials, two parties,
  delegation, groups, recovery. `cargo test -p keri-sdk` runs them all
  against real in-process witnesses.

## Two layers

The crate root is the **facade**: a handful of types, plain-string ids,
automatic retries, no protocol jargon. `keri_sdk::advanced` is the
**mid-level SDK** underneath: the alias-based `KeriStore`, the low-level
`Identifier`, compound `operations`, CESR helpers — for custom flows,
weighted thresholds, out-of-band transports, or building tooling. The facade
is a thin layer over `advanced`; both write the same on-disk store, so you
can mix them.
