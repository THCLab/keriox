# Changelog

All notable changes to this project will be documented in this file.

## [0.17.0-rc3] - 2025-03-26

### 🐛 Bug Fixes

- Refactor escrow database
- Adjust delegation tests
- Validate receipt signatures in pw escrow
- Allow setting next threshold in group incept

### 🚜 Refactor

- Add partially witnessed escrow submodule
- Adjust partially escrow tests

### ⚙️ Miscellaneous Tasks

- Remove unused imports

## [0.17.0-rc2] - 2025-03-12

### 🐛 Bug Fixes

- Update watcher dependencies
- Update failing test

### ⚙️ Miscellaneous Tasks

- Update dependencies

## [0.17.0-rc1] - 2025-02-27

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

### 🚜 Refactor

- Remove unnecessary clone
- Split redb module into multiple files

### 🧪 Testing

- Add delegation tests
- Add assertions for key_state in test_retrieve_kel

### ⚙️ Miscellaneous Tasks

- Reformat and fix warnings
- Add processing events benchmark
- Cargo fmt and update test
- Update rust version in dockers

## [0.16.0] - 2025-01-29

### 🚀 Features

- Add NontransferableIdentifier struct
- Add limit argument to query
- Setup infrastructure for tests

### 🐛 Bug Fixes

- Warnings and failing tests
- Fix test_updates

### ⚙️ Miscellaneous Tasks

- Release

## [0.15.1] - 2025-01-16

### 🐛 Bug Fixes

- Add bundled feat to rusqlite

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

### Refacor

- Add database/sled submodule

### Refacrtor

- Database module cleanup

## [0.14.2] - 2024-12-11

### 🚀 Features

- Save last asked index in database

### ⚙️ Miscellaneous Tasks

- Update README.md
- Release

## [0.14.1] - 2024-12-06

### 🐛 Bug Fixes

- Extract routes
- Append instead of start from scratch after each restart

### ⚙️ Miscellaneous Tasks

- Update README.md
- Release

## [0.14.0] - 2024-11-25

### 🚀 Features

- Add info endpoint for witness and watcher

### ⚙️ Miscellaneous Tasks

- Release

## [0.13.0] - 2024-09-04

### 🚀 Features

- Expose `verify_from_cesr` function

### ⚙️ Miscellaneous Tasks

- Release

## [0.12.7] - 2024-08-30

### 🐛 Bug Fixes

- *(watcher)* Accept query without sn
- *(watcher)* Improve efficiency

### ⚙️ Miscellaneous Tasks

- Update README.md
- Update README.md
- Update README.md
- Release

## [0.12.6] - 2024-08-08

### ⚙️ Miscellaneous Tasks

- Update ci.yml
- Create publish.yml
- Release

## [0.12.5] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Add CHANGELOG.md
- Release

## [0.12.4] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
- Release

## [keri-controller-v0.12.3] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Release

## [keri-controller-v0.12.2] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
- Release

## [keri-controller-v0.12.1] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
- Release

## [keri-controller-v0.12.0] - 2024-08-07

### 🐛 Bug Fixes

- *(watcher)* Prevent overwriting tel

## [witness-v0.1.1] - 2024-08-05

### ⚙️ Miscellaneous Tasks

- Release

### Chore

- Update cargos

## [teliox-v0.4.1] - 2024-08-01

### 🚀 Features

- Make watcher resolve registry id oobi
- Add tel to watcher

### 🐛 Bug Fixes

- Update receipt storing
- Free identifier if response not ready
- Query watchers parallelly
- Publish events to witness parallelly
- Query witnesses parallerlly
- Fix tests
- Remove unwraps
- Minor refactor
- Add route for query tel
- *(watcher)* Store tel to forward in file
- *(watcher)* Save registry ids in file
- Set watcher storage paths in tests

### 🚜 Refactor

- Change ResponseNotReady to NotFound
- Restructure watcher module
- Minor changes

### ⚙️ Miscellaneous Tasks

- Add comments to config files
- Reformat and minor refactor
- Add release section
- Update README
- Update release section
- Release

### Fi

- Make watcher collect tels for identifier

## [teliox-v0.4.0] - 2024-05-21

### 🚀 Features

- Notify if any updates after finalize_query
- Track finalize_query outcome

### 🐛 Bug Fixes

- Broadcast witness receipts to all witnesses
- Align workspaces with previous changes
- Fix failing test
- Split `finalize_query`
- Fix errors
- Tests in keriox_tests module
- Clippy warnings
- Don't save the same receipt twice
- Fix failing test
- Features build error

### 🚜 Refactor

- Add verification error
- Add MoreInfo error
- Split MechanincsError
- Rename functions
- Add mechanics submodule
- Cargo fmt

### ⚙️ Miscellaneous Tasks

- Release

### Fea

- Add MechanicsError

## [keri-controller-v0.3.0] - 2024-04-11

### 🐛 Bug Fixes

- Watcher gets receipts from all witnesses
- Fix quering watcher
- Fix signing and verifing
- Fix test_tel_managing
- Fix group_incept test
- Fix delegation test
- Fix tests module
- Update sign function
- Add watcher to `tel_from_witenss` test

### 🚜 Refactor

- Minor changes and reformat
- Rename Controller -> KnownEvents
- Separate communication from KnownEvents
- Add new Controller and Identifier structures
- Add kel managing submodule
- Add publishing submodule
- Remove unused code
- Cargo fmt
- Fix clippy warnings
- Reformat and cleanup
- Tests cleanup

### ⚙️ Miscellaneous Tasks

- Release

## [teliox-v0.3.0] - 2024-03-22

### 🐛 Bug Fixes

- Allow setting next threshold in rotation
- Impl serialize and deserialize for SeedPrefix
- *(controller)* Store events that need to be publish
- Reformat and cargo clippy
- Tests
- Add logs rout to queries
- Allow get kel until sn
- Remove log route
- Fix failing tests
- Save not fully witnessed state
- Fix errors

### 🧪 Testing

- Add basic kel managing test
- Add test for kel with witness
- Add comments
- Add watcher to `indirect_mode_signing` test
- Add witness rotation test
- Update signing test
- Update watcher tests

### ⚙️ Miscellaneous Tasks

- Add description
- Release
- Update README.md
- Release

### Build

- Update watcher.Dockerfile

## [teliox-v0.2.0] - 2024-01-24

### ⚙️ Miscellaneous Tasks

- Update cargo toml
- Add description
- Release

## [keri-core-v0.9.0] - 2024-01-24

### 🐛 Bug Fixes

- Fix clippy warnings

### ⚙️ Miscellaneous Tasks

- Update package name
- Update cargo.toml
- Update cargo.toml
- Rename package controller to keri-controller
- Release

## [0.4.1-tel] - 2023-07-19

### Action

- Fix repo name for action
- Change to main repo instead of fork

### Actions

- Set custom name of the docker file

## [0.1.0] - 2023-03-29

### 🚀 Features

- *(eq)* Derive PartialEq for lots of stuff
- *(get_kerl)* Impl get_kerl on db and processor
- *(keri)* Add get_state_for_seal function
- *(thresh)* Add WeightedThreshold to KeyConfig
- *(thresh)* Update verify in KeyConfig
- *(thresh)* Update threshold serialization
- *(thresh)* Fix threshold parsing
- *(thres)* Add multi clauses threshold
- *(ev_msg)* Add Counter enum
- *(parse)* Move parsing counter to parse module
- *(del)* Add atachements to SignedEventMessage
- *(del)* Remove seal from delegating event
- *(delegation)* Fix validate seal test
- *(delegation)* Fix delegation test
- *(delegation)* Add pack sn function
- *(delegation)* Minor refactor
- *(attachment)* Add event seal as atachment
- *(parse)* Add attachment parsing
- *(msg_builder)* Add receipts builder
- *(qry)* Add structs for qry message
- *(qry)* Add generic argument to EventMessage
- *(qry)* Add query msg parsing
- *(qry)* Add query messages parsing
- *(qry)* Refactor Attachment enum
- *(qry)* Add qry message processing
- *(rpy)* Add reply message draft
- *(qry)* Add `ksn` msg
- *(qry)* Add KeyStateNotice serialization
- *(qry)* Reply with ksn on qry message
- *(qry)* Add ksn message escrow
- *(rpy)* Add ksn processing draft
- *(qry)* Add bada logic and ksn processing tests
- *(qry)* Add query escrow
- *(ev_msg)* Add event digest checking
- *(state)* Allow weighted witness threshold
- *(witness)* Check if there's enough receipts
- *(escrow)* Add partially witnessed event escrow
- *(witness rot)* Add witness rotation test
- *(witness)* Add function for getting receipts
- *(witness)* Add processor for witness
- *(escrow)* Add out of order escrow
- *(escrow)* Add partially signed escrow
- *(key_config)* New next keys format
- *(parsing)* Add indexed witness sigs parsing
- *(rot)* Add partial rotation test
- *(rot)* Split test for simple and weighted thres
- *(oobi)* Prepare Reply msg for oobis
- *(oobi)* Implement hash and eq
- *(oobi)* Add oobi module
- *(oobi)* Add get oobi func
- *(oobi)* Add getters to oobi struct
- *(oobi)* Add oobi contructor
- *(oobi)* Parse oobi from url
- *(oobi)* Use url instead of string
- *(oobis)* Add database for oobis
- *(oobi)* Add end/role/cut route
- *(oobi)* Implement notifier for oobi manager
- Initial gossip impl (#5)
- *(parsing)* Add first seen attahcment parsing
- *(attachment)* Process attached witness receipt
- *(proc)* Add query message preocessing
- *(demo)* Add witness binary
- *(demo)* Add issuer-witness demo
- *(qry)* Process query message
- *(demo)* Add watcher binary
- Ignore not signed events while escrowing
- Remove stale events from out of order escrow
- Remove stale data from partially signed escrow
- Add partially witness escrow cleanup
- *(watcher)* Sync latest ksn
- Transport trait (#29)

### 🐛 Bug Fixes

- *(seed)* Make key generation match keripy
- *(keri)* Update responding to icp event
- *(keri)* Add get_kerl function
- *(keri)* Fix vrc generation
- *(vrc)* Remove validator receipt event type
- *(test)* Update test_process_receipt
- *(rct)* Transferable receipts parsing + reformat
- *(tests)* Update and fix tests
- *(processor)* Fix get_keys_at_event
- *(test)* Comment tests that need delegation update
- *(key)* Remove derive (de)serialize for priv key
- *(tests)* Fix tests and reformat
- *(codes)* Move code calculations to payload_type
- *(attachement)* Change structures names
- *(all)* Fix typos
- *(ev_builder)* Pass prefix by ref
- *(del)* Remove DelegatedRotationEvent struct
- *(attachement)* Return error instead of todo
- *(msg builder)* Derive prefix from multiple keys
- *(msg_builder)* Allow setting next threshold
- *(keri)* Remove unused argument
- *(msg_builder)* Reformat
- *(ev_msg)* Nontransferable receipts parsing
- *(transrct)* Remove attached seal from prefix mod
- *(test)* Fix delegation test
- *(qry)* Remove unused code
- *(tests)* Fix event parsing tests
- *(test)* Update test vectors in parse module
- *(tests)* Update test vectors
- *(icp)* Fix digest computing for inception event
- *(tests)* Fix qry and rpy parsing tests
- *(test)* Test_process_receipt
- *(tests)* Fix delegation tests
- *(tests)* Update test vectors
- *(tests)* Fix query tests
- *(test)* Fix ksn test
- *(direct_mode)* Fix returning receipts
- *(test)* Fix direct_mode_test
- *(ev_msg_builder)* Set witness_threshold
- *(witness)* Remove todo
- *(keri)* Remove todo
- *(escrow)* Avoid saving the same receipt
- *(test)* Fix process query test
- *(witness)* Accept partially witnessed event
- *(tests)* Fix reply escrow test
- *(all)* Fix building issue
- *(test)* Fix witness rotation test
- *(all)* Fix clippy warnings
- *(witness)* Add functions for getting events
- *(tests)* Fix tests in event_parsing module
- *(test)* Fix more tests
- *(tests)* Update test vectors
- *(test)* Update processor tests
- *(test)* Fix next commitment test
- *(tests)* Fix query tests
- *(key_config)* Remove unused code
- *(test)* Fix signed message parsing test
- *(test)* Remove depreciated code
- *(witness)* Use nontrans prefix for witnesse
- *(oobi)* Fix try_from oobi
- *(oobis)* Add role to oobi
- *(features)* Remove oobi from default features
- *(reply)* Fix reply parsing and reformat
- *(test)* Fix query test
- *(test)* Fix witness rotation test
- *(all)* Fix some warnings
- *(parsing)* Fix double import
- *(all)* Fix build error
- *(demo)* Set watcher priv key
- *(bin)* Fix watcher and witness binaries
- *(demo)* Use seed instead of priv key in config
- *(demo)* Add_initial oobis to watcher config
- *(demo)* Remove tcp settings
- *(demo)* Update witness and watcher demo
- Update anchor function in controller
- Add missing signatures verification
- Save escrowed events into separate file

### 🚜 Refactor

- *(keri)* Update keri mod to use processor
- *(keri)* Use event_msg_builder
- *(signer)* Add KeyManager trait
- *(thresh)* Add separate threshold mod
- *(thresh)* Rename limen
- *(thresh)* Refactor enough_sigs function
- *(signer)* Refactor CryptoBox struct
- *(keys)* Split keys into public and private
- *(keys)* Move public key back to keys module
- *(signer)* Remove seeds from cryptobox
- *(ev_msg)* Separate signed message submodule
- *(log)* Remove log module
- Use notification bus as processor field
- Enable choosing processing strategy
- Make process return messages
- Change processor module structure
- Move oobi processing to component
- Remove respond function
- Update witness tests
- Move witness_processor to witness crate
- Remove direct mode test
- Remove component struct
- Remove clone
- Rename base module to actor
- Remove components/controller workpsace
- Features cleanup
- Remove unwraps
- Split processor and escrow tests

### 🧪 Testing

- *(seed)* Add keypair derivation test
- *(thres)* Add verify test
- *(parse)* Add attachment parsing test
- *(rpy)* Add reply escrow test
- *(qry)* Add query message test
- *(processor)* Add not fully witnessed test
- *(escrow)* Add partially signed test
- *(oobi)* Add oobi tests
- Query mbx with multiple controllers
- Ksn query forwarding

### ⚙️ Miscellaneous Tasks

- *(ursa)* Change ursa branch ref to main
- *(ursa)* Pin ursa commit to pre-build-issues

### Wip

- High level multisig functions

### Fer

- *(all)* Reformat code

### Ref

- *(all)* Remove unwraps
- *(all)* Remove unused code and unwraps
- *(ev_msg)* Move parsing to separate module
- *(parse)* Fix tests
- *(parse)* Fix tests
- *(parse)* Move prefix parsing to parse module
- *(parse)* Move payload type to parse module
- *(parse)* Move serialization to parse module
- *(parse)* Rename Deserialized to Message
- *(ev_msg)* Add convesion to common message type
- *(parsing_mod)* Restructure parsing module
- *(tests)* Remove unused code
- *(event_parsing)* Remove unused code
- *(qry)* Remove generic argument from Envelope
- *(qry)* Query module reformat
- *(state)* Add fields to IdentifierState
- *(qry)* Fix query test and reformat
- *(parsing)* Add common enum for parsed events
- *(qry)* Fix async_processing
- *(qry)* Minor refactor
- *(event)* Separate receipt event from EventData
- *(event)* Add SaidEvent wrapper
- *(state)* Use last event digest in state
- *(all)* Remove unused Option
- *(EventType)* Stop using string as event type
- *(ev_msg)* Split mod.rs into multiple files
- *(tests)* Remove unused code
- *(all)* Fix clippy warnings
- *(state)* Add WitnessConfig struct
- *(witness)* Remove CryptoBox from Witness
- *(processor)* Separate event validation logic
- *(processor)* Add EventStorage struct
- *(escrow)* Use observer for escrow
- *(escrow)* Add Reply Escrow
- *(qry)* Remove redundant error type
- *(witness)* Remove unnecessary code
- *(escrow)* Minor refacotr
- *(all)* Remove unwraps
- *(all)* Minor refactor
- *(escrow)* Add db reference to escrows
- *(processor)* Renaming
- *(processor)* Specify notification type
- *(processor)* Add submodule for notification
- *(processor)* Fix clippy warnings
- *(escrow)* Remove unwraps
- *(proc)* Stop returning state from process func
- *(keri)* Move wallet feature funcs to separate file
- *(proc)* Use notification bus in Keri struct
- *(all)* Reformat and fix warnings
- *(all)* Reformat and fix warnings
- *(parse)* Cesr reprezentation of message
- *(witness)* Get signer from argument
- *(witness)* Add getter of db reference
- *(all)* Fix warnings and reformat
- *(oobi)* Remove redundant struct
- *(oobi)* Add mutex to oobi manager
- *(oobi)* Add OobiStorage struct
- *(all)* Minor refactor
- *(reply)* Add common ReplyRoute enum
- *(all)* Minor refactor
- *(oobis)* Add role enum
- *(all)* Remove unused code
- *(all)* Minor refactor and reformat
- *(processor)* Remove unused code
- *(parsing)* Remove unwraps
- *(parsing)* Add event message parsing

### Update

- *(event)* Update event labels and test vectors
- *(rct)* Add transferable receipt serialization
- *(events)* Add digest field to events

## [0.5.0] - 2021-01-26

### 🚀 Features

- *(delegation)* Dip event processing
- *(delegation)* Add delegator field to state
- *(delegation)* Drt event processing
- *(dip)* Verify identifier binding for dip event
- *(event)* Check delegator before applying event
- *(mgpk)* Add messagePack error type & encoder
- *(mgpk)* Impl mgpk_message
- *(mgpk_sed)* Impl sed extraction for mgpk
- *(sa pref)* Impl new icp logic for SA icp
- *(icp)* New inception process for icp and dip
- *(ver binding)* Allow verify_binding to use DummyEvent
- *(no nxt)* Add support for abandonment/no nxt

### 🐛 Bug Fixes

- *(state)* Rename delegated_keys field
- *(msg)* Separate fns for getting inception data
- *(proc)* Escrow delegated out of order events
- *(tests)* Fix seals and event tests
- *(db_test)* Update test vector in db test
- *(db)* Add open/create db tolerance
- *(seal)* Add sn field and update tests
- *(tests)* Update test vectors in delegation test
- *(delegation)* Update validate seal function
- *(receipt)* Rename validator_seal field
- *(process)* Update validator receipt processing
- *(tests)* Update validate seal test

### 🚜 Refactor

- *(labels)* New labels in serialized events
- *(tests)* Refactor event_message test utils
- *(all)* Minor refactor

### 🧪 Testing

- *(proc)* Dip event processing test
- *(delegation)* Drt event processing test
- *(delegation)* Delegated event applying test
- *(event)* Update parsing and processing tests
- *(em)* Update event_message parse test vectors
- *(proc)* Update processor tests

### ⚙️ Miscellaneous Tasks

- *(dfs)* Remove dfs serializer, no longer used

## [0.4.0] - 2020-12-21

### 🚀 Features

- *(rotation)* Semantics of rotation event
- *(ixn)* Initial ixn event structure
- *(seal)* Add seals
- *(rot)* Add data to rot, rename prev -> dig
- *(vrc)* Initial validator receipt definition
- *(signer)* Add signer module
- *(signer)* Add CryptoBox struct
- *(keri)* Add keri module
- *(d evt)* Delegated inception & rotation structures
- *(wits)* All witnesses are basic prefixes, always
- *(nxt)* Verify nxt, update tests
- *(kc)* Ensure sig set params fit key config exactly
- *(db)* Wip new trait
- *(lmdb)* WIP stab at lmdb impl
- *(trait)* Remove generics and lifetimes
- *(db)* Get state from db
- *(bc)* Use bincode for value storage
- *(lmdb)* Impl new and simplify basic insertions
- *(bc)* Use bincode for all writing
- *(proc)* Add event application errors
- *(proc)* Escrow partially signed event
- *(proc)* Process validator receipt
- *(nxt)* Update nxt creation to use xor
- *(icp)* Improved icp creation
- *(kc)* Update keyconfig usage
- *(parse)* Parse &[u8] instead of &str
- *(parse)* Parse gives ref to original bytes
- *(deser)* Add Deserialized enum to get receipts deser right
- *(events)* Make Dip/Drt fields pub and add rct fields
- *(escrow)* Add escrow fns for receipts
- *(proc)* Use Deserialized enum for processing

### 🐛 Bug Fixes

- *(state)* Backhash checking
- *(state)* Serialize last event without signature
- *(vrc)* Use EventSeal instead of just any Seal
- *(dm)* Use EventLog struct
- *(tests)* Generate nxt correctly
- *(evmsg)* Return out of order and duplicate error
- *(proc)* Minor refactor
- *(parse)* Make message non-pub
- *(test)* Fix db test
- *(db)* Use specific witness/non-attached sig types
- *(parse)* Update signed_event_stream_validate
- *(keri)* Update keri/mod for Deserialized
- *(apply)* Apply EventMessage not Event
- *(seal)* Fix seal deserialization

### 🚜 Refactor

- *(clean)* Remove unused extra seals, use verify_binding
- *(keys)* Make KeyConfig useful, use in State
- *(dlgt)* Remove delegated state, unused
- *(db)* Move higher fns to trait def
- *(proc)* Split into multiple files
- *(ser)* Dont use & for enums
- *(ver)* Remove Verifiable trait, doesnt always fit
- *(proc)* Avoid clones and fix borrows with match

### 📚 Documentation

- *(rct)* Add some context doc to receipt types

### 🧪 Testing

- *(prefix)* Add prefix serialization tests
- *(event_msg)* Test applying event msg to state
- *(ixn)* Test applying ixn event msg to state
- *(dm)* Add direct mode test
- *(db)* Add basic test for dbs
- *(proc)* Test process function
- *(proc)* Add process receipt test
- *(nxt)* Add test for correct nxt creation
- *(nxt)* Minor neatness
- *(all)* Update tests so they run
- *(proc)* Update test vectors
- *(parse)* Event parsing test
- *(proc)* Make `test_process` pass

### ⚙️ Miscellaneous Tasks

- *(license)* Add DIF as licensor

## [0.3.0] - 2020-09-17

### 🚀 Features

- *(icp_ver)* Validate icp event prefixes
- *(dc)* Impl derivation codes themselves
- *(sigs)* Add attached sig codes
- *(prefix)* Use codes in prefix impls
- *(sigs)* Improve ergo, fix attached sig struct

### 🐛 Bug Fixes

- *(event_sig)* Use correct data for event sig/ver
- *(RoT)* Fix verifying identifier and tests

### 🧪 Testing

- *(parse)* Fix test with new sig ver
- *(stream)* Fix test fail case, add new case
- *(pref)* Add prefix test and ev len check test

## [0.2.0] - 2020-09-10

### 🚀 Features

- *(deps)* Add ursa as dependancy
- *(wasm)* Add wasm-bindgen as a dependancy
- *(derivation)* Initial empty impl
- *(derivation)* Initial enum
- *(drv)* Impl FromStr+PartialEq+Display for Derivation
- *(drv)* Add stubbed derivation procedure modules
- *(drv)* Implement blake2b and the SHA digests
- *(drv)* Impl Debug for Derivation
- *(wasm)* Expose derivation procedures to wasm
- *(prefix)* Initial prefix mod added
- *(prefix)* Prefix struct and stub traits
- *(parse)* Implement FromStr for prefix
- *(prefix)* Padding util fns
- *(prefix)* Impl to_str for Prefix
- *(serde)* Add serde support to Prefix
- *(events)* Initial events mod
- *(configs)* Add KeyConfig and WitnessConfig structs
- *(events)* Add stubbed event data types
- *(events)* Add Event struct & EventData enum
- *(event_message)* Event message struct
- *(events)* Fix EventData ser/der
- *(versioned messages)* Add VersionedEventMessage
- *(dfs ser)* Impl DepthFirstSerializer
- *(error)* Add initial Error type
- *(CryptoError)* Add a wrapper for CryptoError
- *(state)* Initial state type
- *(semantics)* Add EventSemantics trait
- *(Signatory)* Add Signatory type
- *(Delegated)* Add DelegatedIdentifierState type
- *(sem)* Impl EventSemantics for Event and EventMessage
- *(icp)* Impl EventSemantics for icp event
- *(verify)* Defn and use Verifiable trait
- *(verification)* Mostly impl Verifiable
- *(verify)* Impl verify using Prefixes
- *(state)* Derive debug for state
- *(readme)* Add basic readme
- *(deps)* Add convenience wasm-pack optional features
- *(prefix)* Impl a prefix enum type
- *(drv)* Remove unnecessary derivation code
- *(codes)* Update derivation codes
- *(cargo)* Remove unnecessary dep
- *(sigs)* Rename sigs -> idxs
- *(ddo)* Add ddo and convenience fns
- *(validate)* Use kel instead of string
- *(ursa)* Export ursa from lib
- *(el)* Define & impl EventLog
- *(err)* Better ser/de errors
- *(pref)* Better prefix types
- *(pref)* Propagate prefix types
- *(dbug)* Derive Debug on event data types
- *(events)* Update serialized sig representation
- *(clone)* Derive clone for eventmessage
- *(vs)* Add size to version string
- *(delegated)* Wip delegated
- *(selfaddressing)* Test a simple self-addressing
- *(hex)* Use unpadded hex strings for all ints
- *(ser)* Impl better version string logic
- *(sigs)* Impl parsing a signature stream
- *(parse)* Move signed event parsing to file
- *(derive)* Impl derive basic from seed
- *(sed)* Impl parse/transcode of sed from event str
- *(parse)* Impl parse&validate stream
- *(blake3)* Add blake3 digests

### 🐛 Bug Fixes

- *(prefix)* Deriv code strs already padded
- *(sigs)* Fix verification and make sig codes explicit
- *(message)* Fix event message and prefix issues
- *(iwk)* Make IcpWithKeys fields public
- *(m)* Fix parsing and serializing signed events
- *(basic_pref)* Fix ed25519 codes
- *(attached)* Fix codes and index decoding
- *(parsing)* Fix signed json parsing & improve icp
- *(ev parsing)* Fix event sig splitting
- *(sig parse)* Allow incomplete sigs to err, not fail
- *(stream)* Fix fail on no event, stub stream test

### 🚜 Refactor

- *(EventData)* Move EventData def to event_data
- *(state)* Rename State -> IdentityState
- *(sem)* Use Error for result error types
- *(sem)* Move EventSemantics def to state/mod
- *(serde)* Clean up serde renames, threshold types
- *(derivation)* Simplfy and restructure Derivations
- *(utils)* Use refs
- *(sig)* Move sig parsing to file
- *(parse sig)* Rename signature->attached_signature
- *(dfs)* Impl dfs ser more rigourously
- *(sed)* Use transcode fn as recommended

### 📚 Documentation

- *(drv)* Add some basic rustdoc comments
- *(derivation)* Add some rustdoc to Derivation

### 🎨 Styling

- *(use)* Make traits nicer

### 🧪 Testing

- *(prefix)* Add simple tests for Prefix
- *(event)* Add small ser/de test
- *(verify)* Add a unit test for verify
- *(event)* Fix deser test, add prev to rot event
- *(message)* Test for creating/applying an event
- *(event_message)* Fix event message test
- *(stream)* Add test for keriox-generated stream

### ⚙️ Miscellaneous Tasks

- *(rename)* Rename keriox -> keri

<!-- generated by git-cliff -->
