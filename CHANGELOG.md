# Changelog

All notable changes to this project will be documented in this file.

## [0.17.4] - 2025-07-22

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.3] - 2025-07-22

### 🚀 Features

- Enhance database abstraction in keri-core

### 💼 Other

- Clean up imports and apply cargo fmt

### 🚜 Refactor

- Remove transport module from teliox
- Remove unwraps and run cargo fmt
- Use redb in teliox out of order escrow

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.2] - 2025-05-09

### 🚀 Features

- Remove sled from partially signed escrow

### 🐛 Bug Fixes

- Fix failing tests
- *(mailbox)* Prevent saving the same element multiple times
- *(mailbox)* Allow getting messages from index
- Resolve feature dependency issues

### 🚜 Refactor

- Add partially_signed_escrow submodule
- Move tests to partially_signed_escrow submodule
- Remove sled from delegation escrow
- Remove unused code
- Add reply escrow submodule
- Add duplicitous event submodule
- Store accepted replys in redb
- Remove sled from reply escrow
- Use redb for mailbox storage
- Remove SledEventDatabase from keri_core workspace
- Align workspaces with changes
- Remove sled db from oobi module
- Remove sled dependency

### 🧪 Testing

- Add mailbox table test

### ⚙️ Miscellaneous Tasks

- Cargo fmt
- Release

## [0.17.1] - 2025-04-30

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.0] - 2025-04-17

### 🚀 Features

- Add query_cache feature

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.0-rc5] - 2025-04-08

### 🐛 Bug Fixes

- Update finalize group event function

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.0-rc4] - 2025-03-27

### ⚙️ Miscellaneous Tasks

- Release

## [0.17.0-rc3] - 2025-03-26

### 🚀 Features

- Derive rkyv's Archive, Serialize, and Deserialize for IdentifierState
- Persist identifier key states in events_db for better tracking
- Replace compute_state function with get_key_state in EventStorage
- Change keys in database
- Use redb in out of order escrow

### 🐛 Bug Fixes

- Compute signature index instead of using 0
- Return receipts as attachments
- Save published receipts sn in db
- Execute add_kel_finalized_event operations in transaction
- Update witness and watcher workspaces
- Refactor escrow database
- Adjust delegation tests
- Validate receipt signatures in pw escrow
- Allow setting next threshold in group incept

### 🚜 Refactor

- Remove unnecessary clone
- Split redb module into multiple files
- Add partially witnessed escrow submodule
- Adjust partially escrow tests

### 🧪 Testing

- Add assertions for key_state in test_retrieve_kel

### ⚙️ Miscellaneous Tasks

- Add processing events benchmark
- Cargo fmt and update test
- Update dependencies
- Remove unused imports
- Release

## [0.16.0] - 2025-01-29

### 🚀 Features

- Add limit argument to query

### 🐛 Bug Fixes

- Warnings and failing tests

### ⚙️ Miscellaneous Tasks

- Release

## [0.15.1] - 2025-01-16

### ⚙️ Miscellaneous Tasks

- Release

## [0.15.0] - 2025-01-16

### 🚀 Features

- Use redb crate
- Save nontransferable receipts
- Save transferable receipts
- Use redb for event storing
- Implement rkyv traits for SerializationInfo
- Implement rkyv::Serialize for KeiEvent

### 🐛 Bug Fixes

- Update tables keys
- Fix validation test
- Cargo fmt
- Fix failing tests
- Update teliox workspace
- Align workspaces with db changes

### 💼 Other

- Add database/sled submodule
- Database module cleanup

### 🚜 Refactor

- Implement EventDatabase for sled
- Reformat
- Update EventDatabase trait
- Redb submodule cleanup
- Use rkyv crate in redb submodule
- Use rkyv for storing attachments
- Restructure rkyv submodule
- Reformat and fix warnings
- Reformat and fix warnings

### ⚙️ Miscellaneous Tasks

- Release

## [0.14.2] - 2024-12-11

### ⚙️ Miscellaneous Tasks

- Release

## [0.14.1] - 2024-12-06

### ⚙️ Miscellaneous Tasks

- Release

## [0.14.0] - 2024-11-25

### 🚀 Features

- Add info endpoint for witness and watcher

### ⚙️ Miscellaneous Tasks

- Release

## [0.13.0] - 2024-09-04

### ⚙️ Miscellaneous Tasks

- Release

## [0.12.7] - 2024-08-30

### ⚙️ Miscellaneous Tasks

- Release

## [0.12.6] - 2024-08-08

### ⚙️ Miscellaneous Tasks

- Release

## [0.12.5] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Add CHANGELOG.md
- Release

## [0.12.4] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.12.3] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.12.2] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.12.1] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.4.2] - 2024-08-05

### 💼 Other

- Update cargos

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.4.1] - 2024-08-01

### 🐛 Bug Fixes

- Update receipt storing
- Free identifier if response not ready
- Query witnesses parallerlly
- Remove unwraps

### 💼 Other

- Make watcher collect tels for identifier

### 🚜 Refactor

- Change ResponseNotReady to NotFound

### ⚙️ Miscellaneous Tasks

- Add comments to config files
- Reformat and minor refactor
- Release

## [keri-controller-v0.4.0] - 2024-05-21

### 🐛 Bug Fixes

- Align workspaces with previous changes
- Fix failing test
- Fix errors
- Clippy warnings
- Don't save the same receipt twice
- Fix failing test
- Features build error

### 🚜 Refactor

- Minor changes and reformat
- Add verification error
- Add MoreInfo error
- Rename functions
- Cargo fmt

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.2.0] - 2024-03-22

### 🐛 Bug Fixes

- Fix clippy warnings
- Allow setting next threshold in rotation
- Impl serialize and deserialize for SeedPrefix
- Add logs rout to queries
- Allow get kel until sn
- Remove log route
- Fix failing tests
- Fix errors

### 🧪 Testing

- Update signing test

### ⚙️ Miscellaneous Tasks

- Update package name
- Update cargo.toml
- Rename package controller to keri-controller
- Release
- Release

## [0.4.2] - 2023-10-04

### 🚀 Features

- Ignore not signed events while escrowing
- Remove stale events from out of order escrow
- Remove stale data from partially signed escrow
- Add partially witness escrow cleanup
- Transport trait (#29)

### 🐛 Bug Fixes

- Update anchor function in controller
- Add missing signatures verification
- Save escrowed events into separate file

### 💼 Other

- High level multisig functions

### 🚜 Refactor

- Use notification bus as processor field
- Enable choosing processing strategy
- Make process return messages
- Change processor module structure
- Move oobi processing to component
- Remove respond function
- Update witness tests
- Move witness_processor to witness crate
- Remove component struct
- Remove clone
- Rename base module to actor
- Features cleanup
- Remove unwraps
- Split processor and escrow tests

### 🧪 Testing

- Ksn query forwarding

<!-- generated by git-cliff -->
