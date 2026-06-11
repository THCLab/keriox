//! Tests for the SAID, inspection, seed, KEL-export, and multisig-request
//! helpers. All tests here run offline.

use keri_sdk::advanced::{
    inspect::{inspect_stream, AttachmentInfo, PayloadKind},
    keys, signing, ActionRequired, HashFunction, HashFunctionCode, IdentifierConfig, KeriStore,
    MultisigRequest,
};
use tempfile::TempDir;

#[test]
fn test_saidify_json() {
    let data = r#"{"hello":"world","d":""}"#;
    let saidified = signing::saidify_json(data, HashFunctionCode::Blake3_256).unwrap();

    // The digest is computed over the document with `d` set to a
    // full_size-length `#` placeholder.
    let to_compute = format!(r#"{{"hello":"world","d":"{}"}}"#, "#".repeat(44));
    let expected_said =
        HashFunction::from(HashFunctionCode::Blake3_256).derive(to_compute.as_bytes());

    let json: serde_json::Value = serde_json::from_str(&saidified).unwrap();
    assert_eq!(
        json.get("d").and_then(|d| d.as_str()).unwrap(),
        expected_said.to_string()
    );

    // Field order is preserved.
    assert!(saidified.starts_with(r#"{"hello":"world","d":""#));

    // Missing `d` field is an error.
    assert!(signing::saidify_json(r#"{"hello":"world"}"#, HashFunctionCode::Blake3_256).is_err());
    // Non-JSON input is an error.
    assert!(signing::saidify_json("not json", HashFunctionCode::Blake3_256).is_err());
}

#[test]
fn test_compute_said() {
    let data = b"hello world";
    let said = signing::compute_said(data, HashFunctionCode::Blake3_256);
    assert!(said.verify_binding(data));
    assert_eq!(said, signing::content_sai(data));

    let sha_said = signing::compute_said(data, HashFunctionCode::SHA2_256);
    assert!(sha_said.verify_binding(data));
    assert_ne!(said.to_string(), sha_said.to_string());
}

#[test]
fn test_seed_from_code() {
    use base64::decode_config;

    // Too-short secret key is rejected.
    assert!(keys::seed_from_code("A", vec![0]).is_err());

    let secret = decode_config(
        "v+zH6O2Hykv4Gtw287PBWC3FwZ/Fs+x0yXhe8Cjzofg=",
        base64::STANDARD,
    )
    .unwrap();
    let seed = keys::seed_from_code("A", secret).unwrap();
    use keri_sdk::advanced::CesrPrimitive;
    assert!(seed.to_str().starts_with('A'));

    // Unknown code is rejected.
    assert!(keys::seed_from_code("!", vec![0; 32]).is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_sign_inspect_roundtrip() {
    let tmp = TempDir::new().unwrap();
    let store = KeriStore::open(tmp.path().to_path_buf()).unwrap();
    let (id, signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();

    let envelope = signing::sign(&id, &signer, b"hello world").unwrap();

    let (parts, rest) = inspect_stream(envelope.cesr.as_bytes()).unwrap();
    assert!(rest.is_empty());
    assert_eq!(parts.len(), 1);
    let part = &parts[0];
    assert_eq!(part.payload_kind, PayloadKind::Json);
    assert!(!part.attachments.is_empty());

    // The signature must surface as a transferable group anchored to the
    // signer's KEL with one indexed signature at index 0.
    let transferable = part
        .attachments
        .iter()
        .find_map(|att| match att {
            AttachmentInfo::TransferableGroups(groups) => Some(groups),
            _ => None,
        })
        .expect("expected a transferable signature group");
    assert_eq!(transferable.len(), 1);
    use keri_sdk::advanced::CesrPrimitive;
    assert_eq!(transferable[0].identifier, id.id().to_str());
    assert_eq!(transferable[0].signatures.len(), 1);
    assert_eq!(transferable[0].signatures[0].index, Some(0));
    assert_eq!(transferable[0].signatures[0].algorithm, "Ed25519 signature");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_get_kel_cesr() {
    let tmp = TempDir::new().unwrap();
    let store = KeriStore::open(tmp.path().to_path_buf()).unwrap();
    let (id, _signer) = store
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();

    let own_kel = id.get_own_kel_cesr().expect("own KEL exists").unwrap();
    assert!(own_kel.contains(r#""t":"icp""#));

    let same_kel = id.get_kel_cesr(id.id()).expect("KEL by id exists").unwrap();
    assert_eq!(own_kel, same_kel);

    // The exported CESR parses back into one part with attachments.
    let (parts, rest) = inspect_stream(own_kel.as_bytes()).unwrap();
    assert!(rest.is_empty());
    assert_eq!(parts.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_multisig_request_json_roundtrip() {
    use keri_core::event_message::signed_event_message::Notice;
    use keri_core::mailbox::exchange::ForwardTopic;

    let tmp = TempDir::new().unwrap();
    let store = KeriStore::open(tmp.path().to_path_buf()).unwrap();
    let (id, _signer) = store
        .create("carol", IdentifierConfig::default())
        .await
        .unwrap();

    // Use the inception event as a stand-in pending group event.
    let notices = id.get_own_kel().unwrap();
    let event = notices
        .iter()
        .find_map(|n| match n {
            Notice::Event(signed) => Some(signed.event_message.clone()),
            _ => None,
        })
        .expect("inception event in own KEL");
    let exchange =
        keri_core::actor::event_generator::exchange(id.id(), &event, ForwardTopic::Multisig);

    let request =
        MultisigRequest::try_from(ActionRequired::MultisigRequest(event.clone(), exchange))
            .unwrap();
    assert!(request.is_inception());
    assert_eq!(request.group_prefix(), *id.id());

    // JSON persistence roundtrip preserves digest, prefix, and event type —
    // this is the dkms `requests` database format.
    let event_json = request.event_json().unwrap();
    let exchange_json = request.exchange_json().unwrap();
    let restored = MultisigRequest::from_json(&event_json, &exchange_json).unwrap();
    assert_eq!(
        restored.event_digest().unwrap(),
        event.digest().unwrap()
    );
    assert!(restored.is_inception());
    assert_eq!(restored.group_prefix(), *id.id());
    assert_eq!(restored.event_json().unwrap(), event_json);
    assert!(request.event_json_pretty().unwrap().contains("\"t\": \"icp\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn test_verify_from_cesr_detailed_unknown_signer() {
    let tmp = TempDir::new().unwrap();
    let store = KeriStore::open(tmp.path().to_path_buf()).unwrap();
    let (alice, alice_signer) = store
        .create("alice", IdentifierConfig::default())
        .await
        .unwrap();

    // Bob has never seen Alice's KEL.
    let tmp2 = TempDir::new().unwrap();
    let store2 = KeriStore::open(tmp2.path().to_path_buf()).unwrap();
    let (bob, _bob_signer) = store2
        .create("bob", IdentifierConfig::default())
        .await
        .unwrap();

    let envelope = signing::sign(&alice, &alice_signer, b"hello").unwrap();

    // Alice verifies her own envelope.
    assert!(alice
        .verify_from_cesr_detailed(envelope.cesr.as_bytes())
        .is_ok());

    // Bob gets a typed issue rather than a flattened error string.
    let issues = bob
        .verify_from_cesr_detailed(envelope.cesr.as_bytes())
        .unwrap_err();
    assert!(!issues.is_empty());
    use keri_sdk::advanced::VerificationIssue;
    assert!(issues.iter().all(|issue| matches!(
        issue,
        VerificationIssue::MissingEvent { .. } | VerificationIssue::UnknownSigner { .. }
    )));
}
