//! Compile-time parity audit: everything `dkms-bin` (the reference
//! consumer) uses must stay reachable through `keri_sdk::advanced` now that
//! the crate root only exposes the high-level facade.
//!
//! This test has no runtime assertions — resolving the paths IS the test.

#![allow(unused_imports)]

use keri_sdk::advanced::{
    // Compound operations dkms-bin drives directly.
    operations::{
        accept_multisig_event, create_multisig, incept_group_registry, incept_registry, issue,
        issue_group, poll_group_requests, poll_pending_requests, revoke,
    },
    // TEL queries.
    tel::{check_credential_status, get_credential_status, query_tel},
    // Signing / SAID helpers.
    signing::{compute_said, parse_signed_envelope, saidify_json},
    // Key generation.
    keys::{generate_ed25519_seed, seed_from_code},
    // CESR stream inspection.
    inspect::inspect_stream,
    // Core types and traits.
    ActionRequired,
    BasicPrefix,
    CesrPrimitive,
    Controller,
    EndRole,
    EphemeralIdentifier,
    HashFunctionCode,
    Identifier,
    IdentifierConfig,
    IdentifierPrefix,
    KeriStore,
    LocationScheme,
    MultisigConfig,
    MultisigRequest,
    Oobi,
    QueryEvent,
    QueryResponse,
    Role,
    SeedPrefix,
    SelfAddressingIdentifier,
    SelfSigningPrefix,
    SerializationFormats,
    SignatureThreshold,
    Signer,
    StoreRotationConfig,
    TelState,
    WatcherResponseError,
};

// Full crate re-exports for anything not individually surfaced.
use keri_sdk::advanced::raw::{cesrox, keri_controller, keri_core, said, teliox};

#[test]
fn identifier_methods_used_by_dkms_resolve() {
    // Methods are checked by referencing them as function items; this
    // compiles only if the signatures still exist.
    let _ = Identifier::query_full_log;
    let _ = Identifier::finalize_query;
    let _ = Identifier::resolve_oobi;
    let _ = Identifier::send_oobi_to_watcher;
    let _ = Identifier::get_location;
    let _ = Identifier::get_role_location;
    let _ = Identifier::find_state;
    let _ = Identifier::get_last_event_seal;
    let _ = Identifier::witnesses;
    let _ = Identifier::registry_id;
    let _ = Identifier::find_vc_state;
    let _ = Identifier::sign_to_cesr;
    let _ = Identifier::verify_from_cesr_detailed;

    let _ = KeriStore::open;
    let _ = KeriStore::create_with_seeds;
    let _ = KeriStore::load;
    let _ = KeriStore::load_signer;
    let _ = KeriStore::rotate_with;
    let _ = KeriStore::save_registry;
    let _ = KeriStore::list_aliases;

    // Threshold variants used by dkms-bin config parsing.
    fn _thresholds(t: SignatureThreshold) {
        match t {
            SignatureThreshold::Simple(_) => {}
            SignatureThreshold::Weighted(_) => {}
        }
    }
}
