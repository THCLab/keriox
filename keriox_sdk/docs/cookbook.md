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
| end an identity for good | `identity.abandon().await` (`abandon_with_provider` for provider keys; a delegated identity returns the request for its delegator; once the approval is received, call it again) |
| check whether an identity is abandoned | `identity.is_abandoned()`; for anyone else's, its state after `import_contact` (`advanced::Identifier::find_status`) |
| destroy an identity's keys and local data | `keri.remove_identity("alias")` |
| check that my witnesses/watchers enforce abandonment | `advanced::supports_abandonment(&url).await` |
| ask a witness/watcher whether an identifier is abandoned (a hint) | `advanced::fetch_identifier_status(&url, &aid).await` |

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
| issue a revocable credential | `identity.issue(schema, attributes).await` (its registry is created with it) |
| hand it to the holder | `credential.presentation` |
| check whether a presented one is still valid | `keri.verify_credential(&presentation)?.is_valid()` |
| revoke one I issued | `identity.revoke(&id).await` (returns the revoked presentation) |
| the current presentation of one I issued | `identity.presentation(&id)` |
| list what I've issued | `identity.credentials()` |
| issue from a group | `group.issue(schema, attributes).await` (deliver the co-signing messages it returns) |
| hand it to someone (IPEX grant) | `identity.grant(&presentation, &their_id, "message")`, deliver the bytes |
| receive a granted credential | `identity.receive_grant(&grant)` (verifies the sender, judges the credential) |
| acknowledge a grant (IPEX admit) | `identity.admit(&grant, "message")`, then `identity.receive_admit(&admit)` on the other side |
| build ACDCs with edges, rules, graduated disclosure | `keri_sdk::acdc` with `advanced::registry::issue` |

## Backup & recovery

| I want to… | Call |
|---|---|
| back an identity up | `identity.export()` → serializable `IdentityBackup` (**contains secrets — encrypt it**) |
| restore after device loss | `keri.new_identity("alias").restore_from(backup).build().await` |

## Multi-party

| I want to… | Call |
|---|---|
| delegate a sub-identity (phone, service) | `keri.new_identity("phone").witness(url).delegated_by(&main_id).build_delegation_request().await` |
| deliver a delegation request | `handle.requests()` — send each `Outgoing` to its `to` |
| see & approve requests sent to me | `identity.receive(&message).await` → `request.approve()` / `accept_as(alias)`, then deliver what they return |
| finish my side of a delegation | `handle.finalize(&approval).await` (recover the handle after restart with `keri.delegation_in_progress`) |
| start a group identity | `identity.new_group("team").member(&id).threshold(n).initiate().await`, then deliver `invite.invitations()` |
| join one | `receive(&invitation)` → `GroupRequest::accept_as("team")`, then deliver its messages |
| use the group later | `keri.group("team")`, then `sign` / `issue` / `rotate` / `sync` |
| out-of-band (witness-less) delegation | `advanced::operations::{build_delegation_request, build_delegation_approval, finalize_delegation_with_seal}` |
| weighted thresholds, mixed-curve groups | `advanced::` only (`SignatureThreshold::Weighted`, per-member configs) |

## Infrastructure & power tools

| I want to… | Call |
|---|---|
| run my own witness/watcher | the `witness` / `watcher` crates in this workspace (`components/`) |
| run fully in memory (tests, ephemeral) | `Keri::open_with_storage(path, StorageConfig::InMemory)` (zero-file: `KeriStore::open_with_options` + `MemorySecretsStore` + `Keri::from_store`) |
| store events in Postgres | `Keri::open_with_storage(path, StorageConfig::Postgres { url })` (feature `storage-postgres`) |
| use my own seed storage (OS keychain) | implement `advanced::SecretsStore`, pass to `KeriStore::open_with_options` |
| tune network retries | `Keri::open_with(path, RetryPolicy { .. })` |
| fetch a KEL without local state | `advanced::EphemeralIdentifier::{pull_kel, pull_ksn}` |
| query watchers / full logs manually | `advanced::Identifier::{query_full_log, finalize_query}` |
| process a raw KEL CESR stream | `advanced::Controller::process_kel_stream` |
| reach the underlying crates directly | `advanced::raw::{keri_core, keri_controller, teliox, cesrox, said}` |

If you find yourself writing the same `advanced::` sequence repeatedly, that
is a hint the facade is missing a method — please open an issue.
