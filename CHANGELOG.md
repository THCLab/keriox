## [0.17.11] - 2026-03-25

### 🐛 Bug Fixes

- Set correctly version for release commit

### ⚙️ Miscellaneous Tasks

- Remove println causing issue with parsing output
- Bump cesrox and said
- Clean release configuration and provide developer guide
- Improve git cliff and changelog generation
- Fix release version for the commit
- Update changelog, set filter unconvential to false
## [0.17.9] - 2025-09-04

### 🚀 Features

- Add get_state method in keri-sdk to retrieve identifier state
- Add `from_sn`, `limit` parameters for `get_log_query` in keri-sdk
## [0.17.8] - 2025-08-27

### 🐛 Bug Fixes

- Add "oobi" feature to keri-core dependency in keri-sdk
## [0.17.7] - 2025-08-27

### 🚀 Features

- In keri-sdk add watcher management and loading identifier

### 🚜 Refactor

- Separate OobiManager into its own module
## [0.17.6] - 2025-07-24

### 🚜 Refactor

- Remove acdc dependency from keri-sdk in test
## [0.17.5] - 2025-07-22

### 🐛 Bug Fixes

- Add version for keri-core dependency in teliox
## [0.17.4] - 2025-07-22

### 🐛 Bug Fixes

- Pin acdc dependency to specific version and revision in keri-sdk
## [0.17.3] - 2025-07-22

### 🚀 Features

- Enhance database abstraction in keri-core
- Use redb to store events
- Add keriox_sdk

### 🐛 Bug Fixes

- Update workspaces

### 🚜 Refactor

- Add database trait in teliox
- Parameterize kel database in teliox
- Remove transport module from teliox
- Remove unwraps and run cargo fmt
- Remove unused feature flags
- Use redb in teliox out of order escrow
- Use redb in teliox missing issuer escrow
- Use redb in teliox missing registry escrow
- Remove sled dependencies
- Update Tel struct to support generic EventDatabase
## [0.17.2] - 2025-05-09

### 🚀 Features

- Remove sled from partially signed escrow

### 🐛 Bug Fixes

- Fix failing tests
- Use index in table instead of event sn in mailbox db
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
## [0.17.1] - 2025-04-30

### 🚜 Refactor

- Update verify_from_cesr arguments
## [0.17.0] - 2025-04-17

### 🚀 Features

- Add query_cache feature

### 🐛 Bug Fixes

- Remove async-std from watcher
- Update tests workspace
## [0.17.0-rc5] - 2025-04-08

### 🚀 Features

- Add finalize_group_event function

### 🐛 Bug Fixes

- Update incept_registry and issue functions
- Update finalize group event function
## [0.17.0-rc4] - 2025-03-27

### 🐛 Bug Fixes

- Correct test failures
- Correct signature index computation
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
## [0.15.1] - 2025-01-16

### 🐛 Bug Fixes

- Add bundled feat to rusqlite
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
## [0.14.2] - 2024-12-11

### 🚀 Features

- Save last asked index in database

### ⚙️ Miscellaneous Tasks

- Update README.md
## [0.14.1] - 2024-12-06

### 🐛 Bug Fixes

- Extract routes
- Append instead of start from scratch after each restart

### ⚙️ Miscellaneous Tasks

- Update README.md
## [0.14.0] - 2024-11-25

### 🚀 Features

- Add info endpoint for witness and watcher
## [0.13.0] - 2024-09-04

### 🚀 Features

- Expose `verify_from_cesr` function
## [0.12.7] - 2024-08-30

### 🐛 Bug Fixes

- *(watcher)* Accept query without sn
- *(watcher)* Improve efficiency

### ⚙️ Miscellaneous Tasks

- Update README.md
- Update README.md
- Update README.md
## [0.12.6] - 2024-08-08

### ⚙️ Miscellaneous Tasks

- Update ci.yml
- Create publish.yml
## [0.12.5] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Add CHANGELOG.md
## [0.12.4] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
## [keri-controller-v0.12.2] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
## [keri-controller-v0.12.1] - 2024-08-07

### ⚙️ Miscellaneous Tasks

- Update docker-images.yml
## [keri-controller-v0.12.0] - 2024-08-07

### 🐛 Bug Fixes

- *(watcher)* Prevent overwriting tel
## [keri-controller-v0.4.1] - 2024-08-01

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
## [keri-controller-v0.4.0] - 2024-05-21

### 🚀 Features

- Notify if any updates after finalize_query
- Track finalize_query outcome

### 🐛 Bug Fixes

- Broadcast witness receipts to all witnesses
- Align workspaces with previous changes
- Fix failing test
- Split `finalize_query`
- Fix errors
- Fix failing tests
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
## [keri-controller-v0.2.0] - 2024-03-22

### 🐛 Bug Fixes

- Fix clippy warnings
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

- Update package name
- Update cargo.toml
- Update cargo.toml
- Rename package controller to keri-controller
- Update cargo toml
- Add description
- Add description
- Update README.md
## [0.1.0] - 2023-03-29

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
- *(icp_ver)* Validate icp event prefixes
- *(dc)* Impl derivation codes themselves
- *(sigs)* Add attached sig codes
- *(prefix)* Use codes in prefix impls
- *(sigs)* Improve ergo, fix attached sig struct
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
- *(eq)* Derive PartialEq for lots of stuff
- *(get_kerl)* Impl get_kerl on db and processor
- *(keri)* Add get_state_for_seal function
- Feat(sled) last_event_at_sn() implemented
- Feat(sled) SledEventDatabase proper instantiation
- Feat(sled) tables restructure
- Feat(sled) tables restructure
- Feat(sled) IdentifierPrefix DB id get + set
- Feat(sled) log_event() and last_event_at_sn() impl
- Feat(sled) get_kers() impl
- Feat(sled) tables docs + cleanup
- Feat(sled) has_receipt() impl
- Feat(sled) NEW db api examples to work with structs directly
- Feat(sled) TimestampedEvent impl
- Feat(sled) db getters and setters except receipts
- Feat(sled) v0.7 DB replacement initial
- Feat(sled) processor compute_state & compute_state_at_sn refactor
- Feat(sled) get_last_establishment_event_seal & get_key_at_event refactor
- Feat(sled) validate_seal refactor
- Feat(sled) process_event() refactoring
- Feat(sled) get_kerl() initial refactoring
- Feat(sled) get_kerl() .serialize() refactoring
- Feat(sled) get_kerl pre receipts

Co-authored-by: Edyta Pawlak <edyta@postacnormalna.pl>
- Feat(sled) has_receipt refactoring
- Feat(sled) has_receipt check all under given sn
- Feat(sled) process_validator_receipt refactoring
- Feat(sled) process_witness_receipt part refactoring. receipt transformation needed
- Feat(sled) process_witness_receipt refactoring v2
- Feat(sled) processor refactoring compiles
- Feat(sled) process_validator_receipt refactor allign + keri mod tests
- Feat(sled) get_event_at_sn impl and refactoring
- Feat(sled) keri mod tests refactor compile
- Feat(sled) test_direct_mode ok
- Feat(sled) processor alignment
- *(thresh)* Add WeightedThreshold to KeyConfig
- *(thresh)* Update verify in KeyConfig
- *(thresh)* Update threshold serialization
- *(thresh)* Fix threshold parsing
- *(thres)* Add multi clauses threshold
- Feat(witness rotation) rotation event extended processing
- Feat(witness rotation) minus clone
- Feat(process_escrow) DB remove implementation for some tables
- Feat(unified_tables) out of order table cleanup and compute_state() ignore out_of_order
- Feat(unified_tables) event comparison fix and test improvements
- Feat(unified_tables) out_of_order single table refactoring
- Feat(kerl) transferable receipts inclusion
- Feat(async) processing ALMOST working
- Feat(async) process with String errors
- Feat(async) process with reader only
- Feat(async) async stream processing done
- Feat(crates update) k256, base64 version bumps
- Feat(async) single message processing
- Feat(async) message metadata processing
- Feat(async) whole chunk of received data processing
- Feat(async) KERI instance and response generation
- Feat(async) payload size enum and parser
- Feat(async) payload size parser inclusion
- Feat(async) async processor stream parser improvements
- Feat(async) PayloadType extension with master_code_size() method
- Feat(async) Base64 master code parsing for attachments done
- Feat(async) Arc shared pinned Keri instance
- Feat(serializer) serializer error impl
- Feat(serializer) initial KeriSerializer impl
- Feat(serializer) impl Serializer and SignedEvenMessage serialization with master code
- Feat(serializer) serialization working
- Feat(serializer) additional test
- Feat(serializer) serialization for both DB and qb64 alligned
- Feat(response) respond_single method implementation
- Feat(respones) async respond_single use
- Feat(hash) derive Hash for IdentifierPrefix
- Feat(test) keri test module comile only on tests, not on build
- Feat(async) channel to track processed message for sync purposes
- Feat(async) replaced mpsc::Sender with async_std::channel::Sender
- Feat(async) Arc for DB in Keri instance for safe thread sharing
- Feat(wallet-rs) wallet-rs as KeyProvider; Arc and RefCell for KeyProvider for thread safety;
- Feat(SignedNontransferableReceipt) Keri make_ntr() and generate_ntr() methods
- Feat(NTR) new() and serialize() for NontransferableReceipt
- Feat(wallet) feature annotation move
- Feat(interaction) basic inter-identifier interaction
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
- *(event_sig)* Use correct data for event sig/ver
- *(RoT)* Fix verifying identifier and tests
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
- Fix(ed25519) sig crate update allignment
- Fix(cleanup) warnings cleaned up
- Fix(keri) typo fix
- Fix(incept_with_extra_keys) verification key ordering - should be first
- Fix(warnings) feature-gated async functionality to prevent dead code
- Fixme(event) event named property repetitive cumbersomeness cleanup
- Fix(signatures) faulty signatures detection on verification
- Fix(conflicts) merge conflicts resolution
- *(key)* Remove derive (de)serialize for priv key
- Fix(merge #78) renaming alligned with new changes
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
- Fix field order in query msg
- Fix test_query in witness
- Fix test_qry_rpy in witness
- Fix mbx test
- Fix warnings
- Fix processor tests
- Fix test not fully witnessed
- Fix test_mbx
- Fix test_validate_seal
- Fix controller example
- Fix warnings
- Fix tests
- Fix tests
- Fix oobi processing in controller
- Update anchor function in controller
- Add missing signatures verification
- Fix warnings
- Fix test_ksn_query
- Save escrowed events into separate file
- Fix tests
- Fix remaining errors
- Fix electing leader
- Fix test attempt 1
- Fix error
- Fix errors

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
- *(clean)* Remove unused extra seals, use verify_binding
- *(keys)* Make KeyConfig useful, use in State
- *(dlgt)* Remove delegated state, unused
- *(db)* Move higher fns to trait def
- *(proc)* Split into multiple files
- *(ser)* Dont use & for enums
- *(ver)* Remove Verifiable trait, doesnt always fit
- *(proc)* Avoid clones and fix borrows with match
- *(labels)* New labels in serialized events
- *(tests)* Refactor event_message test utils
- *(all)* Minor refactor
- *(keri)* Update keri mod to use processor
- *(keri)* Use event_msg_builder
- *(signer)* Add KeyManager trait
- Refactoring complete - tests failing
- *(thresh)* Add separate threshold mod
- *(thresh)* Rename limen
- *(thresh)* Refactor enough_sigs function
- *(signer)* Refactor CryptoBox struct
- *(keys)* Split keys into public and private
- *(keys)* Move public key back to keys module
- *(signer)* Remove seeds from cryptobox
- *(ev_msg)* Separate signed message submodule
- *(log)* Remove log module
- Refactor RefCell -> Box for Keri struct's KeyManager
- Use notification bus as processor field
- Enable choosing processing strategy
- Make process return messages
- Change processor module structure
- Move oobi processing to component
- Remove respond function
- Update witness tests
- Move witness_processor to witness crate
- Refactor watcher
- Remove direct mode test
- Remove component struct
- Remove clone
- Rename base module to actor
- Remove components/controller workpsace
- Features cleanup
- Remove unwraps
- Split processor and escrow tests

### 📚 Documentation

- *(drv)* Add some basic rustdoc comments
- *(derivation)* Add some rustdoc to Derivation
- *(rct)* Add some context doc to receipt types
- Docs
- Docs and var names

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
- *(parse)* Fix test with new sig ver
- *(stream)* Fix test fail case, add new case
- *(pref)* Add prefix test and ev len check test
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
- *(proc)* Dip event processing test
- *(delegation)* Drt event processing test
- *(delegation)* Delegated event applying test
- *(event)* Update parsing and processing tests
- *(em)* Update event_message parse test vectors
- *(proc)* Update processor tests
- *(seed)* Add keypair derivation test
- *(thres)* Add verify test
- *(parse)* Add attachment parsing test
- *(rpy)* Add reply escrow test
- *(qry)* Add query message test
- *(processor)* Add not fully witnessed test
- *(escrow)* Add partially signed test
- *(oobi)* Add oobi tests
- Query mbx with multiple controllers
- Test wip 1
- Ksn query forwarding
- Test transport initial impl
- Test remote error
- Test 2 witnesses wip

### ⚙️ Miscellaneous Tasks

- *(rename)* Rename keriox -> keri
- *(license)* Add DIF as licensor
- *(dfs)* Remove dfs serializer, no longer used
- *(ursa)* Change ursa branch ref to main
- *(ursa)* Pin ursa commit to pre-build-issues
