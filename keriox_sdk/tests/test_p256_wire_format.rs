//! End-to-end wire-format test for ECDSA secp256r1 (P-256) support.
//!
//! Walks the full stack:
//!
//!   keri_sdk::keys ->  keri_core::prefix::derive  ->  cesrox CESR codes
//!                  ->  PrivateKey::sign_p256      ->  SelfSigningPrefix
//!                  ->  to_str / from_str          ->  BasicPrefix::verify
//!
//! Mobile clients (iOS Secure Enclave / Android Keystore) that produce
//! secp256r1 signatures must round-trip through exactly this format.

use cesrox::primitives::CesrPrimitive;
use keri_controller::BasicPrefix;
use keri_core::prefix::{SeedPrefix, SelfSigningPrefix};

#[test]
fn p256_full_wire_roundtrip_transferable() {
    let (seed, transferable_pk) = keri_sdk::advanced::keys::generate_p256(true).unwrap();

    assert!(matches!(seed, SeedPrefix::RandomSeed256ECDSA256r1(_)));
    assert!(matches!(transferable_pk, BasicPrefix::ECDSA256r1(_)));
    assert!(transferable_pk.is_transferable());

    let pk_cesr = transferable_pk.to_str();
    assert!(pk_cesr.starts_with("1AAJ"), "transferable P-256 must use 1AAJ code, got {pk_cesr}");
    let parsed_pk: BasicPrefix = pk_cesr.parse().unwrap();
    assert_eq!(parsed_pk, transferable_pk);

    let (_pub_key, priv_key) = seed.derive_key_pair().unwrap();
    let msg = b"keri inception payload for a mobile-native AID";
    let raw_sig = priv_key.sign_p256(msg).unwrap();
    assert_eq!(raw_sig.len(), 64, "P-256 signatures must be raw 64-byte r||s");

    let sig_prefix = SelfSigningPrefix::ECDSA256r1Sha256(raw_sig);
    let sig_cesr = sig_prefix.to_str();
    assert!(sig_cesr.starts_with("0I"), "P-256 sig must use 0I code, got {sig_cesr}");

    let parsed_sig: SelfSigningPrefix = sig_cesr.parse().unwrap();
    assert_eq!(parsed_sig, sig_prefix);

    let ok = parsed_pk.verify(msg, &parsed_sig).unwrap();
    assert!(ok, "P-256 signature must verify after CESR round-trip");

    assert!(
        !parsed_pk.verify(b"tampered", &parsed_sig).unwrap(),
        "verification must reject a tampered message"
    );
}

#[test]
fn p256_nontransferable_uses_distinct_code() {
    let (_seed, nt_pk) = keri_sdk::advanced::keys::generate_p256(false).unwrap();
    assert!(matches!(nt_pk, BasicPrefix::ECDSA256r1NT(_)));
    assert!(!nt_pk.is_transferable());
    assert!(
        nt_pk.to_str().starts_with("1AAI"),
        "non-transferable P-256 must use 1AAI code, got {}",
        nt_pk.to_str()
    );
}

#[test]
fn derive_public_key_handles_p256_seed() {
    let seed = keri_sdk::advanced::keys::generate_p256_seed().unwrap();

    let transferable = keri_sdk::advanced::keys::derive_public_key(&seed, true).unwrap();
    let non_transferable = keri_sdk::advanced::keys::derive_public_key(&seed, false).unwrap();

    assert!(matches!(transferable, BasicPrefix::ECDSA256r1(_)));
    assert!(matches!(non_transferable, BasicPrefix::ECDSA256r1NT(_)));

    // Same seed must yield identical key material under both flavors.
    let (a, _) = seed.derive_key_pair().unwrap();
    let (b, _) = seed.derive_key_pair().unwrap();
    assert_eq!(a.key(), b.key());
}
