# Cookbook: "I want to…"

Quick routing table from intent to API. Facade items live at the crate
root; `advanced::` marks the mid-level layer for cases the facade doesn't
cover.

## Identities

| I want to… | Call |
|---|---|
| create an identity behind a witness | `keri.new_identity("alias").witness(url).build().await` |
| experiment locally, no infrastructure | `keri.new_identity("alias").build().await` (no witnesses) |
| load it again after a restart | `keri.identity("alias")` |
| list what's in my store | `keri.identities()` |
| pick the key algorithm | `.key_algorithm(KeyAlgorithm::P256)` on the builder |
| use mobile-keystore / HSM keys | `.key_providers(current, next)` (feature `keyprovider`) |
| rotate my keys | `identity.rotate().await` |
| add/remove witnesses while rotating | `advanced::KeriStore::rotate_with` + `StoreRotationConfig` |
| create from a deterministic seed (mnemonic) | `advanced::KeriStore::create_with_seeds` |

## Signing & verification

| I want to… | Call |
|---|---|
| sign data | `identity.sign(payload).await` → self-contained CESR string |
| verify a message | `keri.verify(cesr)` → payload + proven signer (offline) |
| verify a stranger's message | first `keri.import_contact(their_oobi_url).await`, then `verify` |
| let others verify me | share `identity.oobi_url()?` (or `identity.kel()?` for offline) |
| pick up a contact's key rotation | `keri.import_contact(...)` again, or it happens automatically in multi-party flows |
| inspect a CESR stream's structure | `advanced::inspect::inspect_stream` |
| compute / embed a SAID | `advanced::signing::{compute_said, saidify_json}` |
| sign without the JSON envelope (raw protocol format) | `advanced::signing::sign_to_cesr` |

## Credentials

| I want to… | Call |
|---|---|
| issue a revocable credential | `identity.issue(payload).await` (registry auto-created) |
| check whether one is still valid | `keri.credential_status(&id).await?.is_valid()` |
| revoke one I issued | `identity.revoke(&id).await` |
| list what I've issued | `identity.credentials()` |
| issue from a group | `group.issue(payload).await` |
| build full ACDC attestations | the `acdc` crate on top of `advanced::signing` helpers |

## Backup & recovery

| I want to… | Call |
|---|---|
| back an identity up | `identity.export()` → serializable `IdentityBackup` (**contains secrets — encrypt it**) |
| restore after device loss | `keri.new_identity("alias").restore_from(backup).build().await` |

## Multi-party

| I want to… | Call |
|---|---|
| delegate a sub-identity (phone, service) | `keri.new_identity("phone").witness(url).delegated_by(&main_id).build_delegation_request().await` |
| see & approve requests addressed to me | `identity.pending_requests().await` → `request.approve()` / `accept_as(alias)` |
| finish my side of a delegation | `handle.finalize().await` (recover the handle after restart with `keri.delegation_in_progress`) |
| start a group identity | `identity.new_group("team").member(&id).threshold(n).initiate().await` |
| join one | `pending_requests()` → `GroupRequest::accept_as("team")` |
| use the group later | `keri.group("team")`, then `sign` / `issue` / `rotate` / `sync` |
| out-of-band (witness-less) delegation | `advanced::operations::{build_delegation_request, build_delegation_approval, finalize_delegation_with_seal}` |
| weighted thresholds, mixed-curve groups | `advanced::` only (`SignatureThreshold::Weighted`, per-member configs) |

## Infrastructure & power tools

| I want to… | Call |
|---|---|
| run my own witness/watcher | the `witness` / `watcher` crates in this workspace (`components/`) |
| tune network retries | `Keri::open_with(path, RetryPolicy { .. })` |
| fetch a KEL without local state | `advanced::EphemeralIdentifier::{pull_kel, pull_tel, pull_ksn}` |
| query watchers / full logs manually | `advanced::Identifier::{query_full_log, finalize_query}` |
| process raw KEL/TEL CESR streams | `advanced::Controller::{process_kel_stream, process_tel_stream}` |
| reach the underlying crates directly | `advanced::raw::{keri_core, keri_controller, teliox, cesrox, said}` |

If you find yourself writing the same `advanced::` sequence repeatedly, that
is a hint the facade is missing a method — please open an issue.
