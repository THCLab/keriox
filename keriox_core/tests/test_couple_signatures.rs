//! Non-transferable signature couples (signer key and signature, as on
//! replies, queries and exchanges) come from the network. A couple that
//! cannot be verified, because its signature type does not match its key or
//! because there is none at all, is a failed verification, never a panic.

use std::sync::Arc;

use keri_core::{
    database::redb::RedbDatabase,
    event_message::signature::{Nontransferable, Signature},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    processor::{event_storage::EventStorage, validator::EventValidator},
    signer::Signer,
};
use tempfile::NamedTempFile;

fn setup() -> (NamedTempFile, Arc<RedbDatabase>) {
    let path = NamedTempFile::new().unwrap();
    let db = Arc::new(RedbDatabase::new(path.path()).unwrap());
    (path, db)
}

const DATA: &[u8] = b"a reply body";

fn couple(signature: SelfSigningPrefix) -> Signature {
    let signer = Signer::new();
    Signature::NonTransferable(Nontransferable::Couplet(vec![(
        BasicPrefix::Ed25519NT(signer.public_key()),
        signature,
    )]))
}

/// An Ed25519 key with a secp256k1 signature, as a crafted couple has it.
fn mismatched() -> Signature {
    couple(SelfSigningPrefix::ECDSAsecp256k1Sha256(vec![0u8; 64]))
}

fn no_couples() -> Signature {
    Signature::NonTransferable(Nontransferable::Couplet(vec![]))
}

#[test]
fn a_couple_whose_signature_type_does_not_match_its_key_fails_verification() {
    let (_path, db) = setup();
    let validator = EventValidator::new(db.clone());
    assert!(validator.verify(DATA, &mismatched()).is_err());
    assert!(!mismatched().verify(DATA, &EventStorage::new(db)).unwrap());
}

#[test]
fn an_empty_couple_group_fails_verification() {
    let (_path, db) = setup();
    let validator = EventValidator::new(db.clone());
    assert!(validator.verify(DATA, &no_couples()).is_err());
    assert!(!no_couples().verify(DATA, &EventStorage::new(db)).unwrap());
    assert_eq!(no_couples().get_signer(), None);
}

#[test]
fn a_valid_couple_still_verifies() {
    let (_path, db) = setup();
    let signer = Signer::new();
    let signature = Signature::NonTransferable(Nontransferable::Couplet(vec![(
        BasicPrefix::Ed25519NT(signer.public_key()),
        SelfSigningPrefix::Ed25519Sha512(signer.sign(DATA).unwrap()),
    )]));
    assert!(EventValidator::new(db.clone())
        .verify(DATA, &signature)
        .is_ok());
    assert!(signature.verify(DATA, &EventStorage::new(db)).unwrap());
    assert_eq!(
        signature.get_signer(),
        Some(IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(
            signer.public_key()
        )))
    );
}
