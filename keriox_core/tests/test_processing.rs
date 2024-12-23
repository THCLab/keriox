use std::{fs, sync::Arc};

use keri_core::{
    actor::{parse_event_stream, parse_notice_stream, process_notice},
    database::{redb::RedbDatabase, sled::SledEventDatabase},
    error::Error,
    event_message::signed_event_message::{Message, Notice},
    prefix::IdentifierPrefix,
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
};
use tempfile::NamedTempFile;

#[test]
fn test_process() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());


    let (processor, storage) = (
        BasicProcessor::new(events_db.clone(), db.clone(), None),
        EventStorage::new(events_db.clone(), db.clone()),
    );

    let icp_raw = br#"{"v":"KERI10JSON0001e7_","t":"icp","d":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"0","kt":"2","k":["DErocgXD2RGSyvn3MObcx59jeOsEQhv2TqHirVkzrp0Q","DFXLiTjiRdSBPLL6hLa0rskIxk3dh4XwJLfctkJFLRSS","DE9YgIQVgpLwocTVrG8tidKScsQSMWwLWywNC48fhq4f"],"nt":"2","n":["EDJk5EEpC4-tQ7YDwBiKbpaZahh1QCyQOnZRF7p2i8k8","EAXfDjKvUFRj-IEB_o4y-Y_qeJAjYfZtOMD9e7vHNFss","EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m"],"bt":"0","b":[],"c":[],"a":[]}-AADAAD4SyJSYlsQG22MGXzRGz2PTMqpkgOyUfq7cS99sC2BCWwdVmEMKiTEeWe5kv-l_d9auxdadQuArLtAGEArW8wEABD0z_vQmFImZXfdR-0lclcpZFfkJJJNXDcUNrf7a-mGsxNLprJo-LROwDkH5m7tVrb-a1jcor2dHD9Jez-r4bQIACBFeU05ywfZycLdR0FxCvAR9BfV9im8tWe1DglezqJLf-vHRQSChY1KafbYNc96hYYpbuN90WzuCRMgV8KgRsEC"#;
    let deserialized_icp = match parse_event_stream(icp_raw).unwrap()[0].clone() {
        Message::Notice(not) => not,
        _ => unreachable!(),
    };

    let id = match &deserialized_icp {
        Notice::Event(e) => e.event_message.data.get_prefix(),
        _ => unreachable!(),
    };

    // Process icp event.
    process_notice(deserialized_icp, &processor)?;

    // Check if processed event is in kel.
    let icp_from_db = storage.get_event_at_sn(&id, 0).unwrap();
    let re_serialized = icp_from_db.signed_event_message.encode().unwrap();
    assert_eq!(icp_raw.to_vec(), re_serialized);

    let rot_raw = br#"{"v":"KERI10JSON00021c_","t":"rot","d":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"1","p":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","kt":"2","k":["DCjxOXniUc5EUzDqERlXdptfKPHy6jNo_ZGsS4Vd8fAE","DNZHARO4dCJlluv0qezEMRmErIWWc-lzOzolBOQ15tHV","DOCQ4KN1jUlKbfjRteDYt9fxgpq1NK9_MqO5IA7shpED"],"nt":"2","n":["EN8l6yJC2PxribTN0xfri6bLz34Qvj-x3cNwcV3DvT2m","EATiZAHl0kzKID6faaQP2O7zB3Hj7eH3bE-vgKVAtsyU","EG6e7dJhh78ZqeIZ-eMbe-OB3TwFMPmrSsh9k75XIjLP"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAAqV6xpsAAEB_FJP5UdYO5qiJphz8cqXbTjB9SRy8V0wIim-lgafF4o-b7TW0spZtzx2RXUfZLQQCIKZsw99k8AABBP8nfF3t6bf4z7eNoBgUJR-hdhw7wnlljMZkeY5j2KFRI_s8wqtcOFx1A913xarGJlO6UfrqFWo53e9zcD8egIACB8DKLMZcCGICuk98RCEVuS0GsqVngi1d-7gAX0jid42qUcR3aiYDMp2wJhqJn-iHJVvtB-LK7TRTggBtMDjuwB"#;
    let deserialized_rot = parse_notice_stream(rot_raw).unwrap()[0].clone();

    // Process rotation event.
    process_notice(deserialized_rot.clone(), &processor)?;
    let rot_from_db = storage.get_event_at_sn(&id, 1).unwrap();
    assert_eq!(rot_from_db.signed_event_message.encode().unwrap(), rot_raw);

    let ixn_raw = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EL6Dpm72KXayaUHYvVHlhPplg69fBvRt1P3YzuOGVpmz","i":"EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen","s":"2","p":"EHjzZj4i_-RpTN2Yh-NocajFROJ_GkBtlByhRykqiXgz","a":[]}-AADAABgep0kbpgl91vvcXziJ7tHY1WVTAcUJyYCBNqTcNuK9AfzLHfKHhJeSC67wFRU845qjLSAC-XwWaqWgyAgw_8MABD5wTnqqJcnLWMA7NZ1vLOTzDspInJrly7O4Kt6Jwzue9z2TXkDXi1jr69JeKbzUQ6c2Ka1qPXAst0JzrOiyuAPACAcLHnOz1Owtgq8mcR_-PpAr91zOTK_Zj9r0V-9P47vzGsYwAxcVshclfhCMhu73aZuZbvQhy9Rxcj-qRz96cIL"#;
    let deserialized_ixn = parse_notice_stream(ixn_raw).unwrap()[0].clone();

    // Process interaction event.
    process_notice(deserialized_ixn, &processor)?;

    // Check if processed event is in db.
    let ixn_from_db = storage.get_event_at_sn(&id, 2).unwrap();
    assert_eq!(ixn_from_db.signed_event_message.encode().unwrap(), ixn_raw);

    let id: IdentifierPrefix = "EBfxc4RiVY6saIFmUfEtETs1FcqmktZW88UkbnOg0Qen".parse()?;
    let mut kel = Vec::new();
    kel.extend(icp_raw);
    kel.extend(rot_raw);
    kel.extend(ixn_raw);

    let db_kel = storage.get_kel(&id)?;

    assert_eq!(db_kel, Some(kel));

    Ok(())
}
