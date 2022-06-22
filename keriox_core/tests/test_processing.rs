use std::sync::Arc;

use keri::{
    actor::prelude::*, database::sled::SledEventDatabase, error::Error,
    event_message::signed_event_message::Op, processor::event_storage::EventStorage,
};

#[test]
pub fn test_ksn_query() -> Result<(), Error> {
    use keri::event_message::signed_event_message::Message;
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path())?);

    let (processor, storage) = (
        BasicProcessor::new(db.clone()),
        EventStorage::new(db.clone()),
    );
    // Process inception event and its receipts. To accept inception event it must be fully witnessed.
    let rcps = r#"{"v":"KERI10JSON000091_","t":"rct","d":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","s":"0"}-BADAAI_M_762PE-i9uhbB_Ynxsx4mfvCA73OHM96U8SQtsgV0co4kGuSw0tMtiQWBYwA9bvDZ7g-ZfhFLtXJPorbtDwABDsQTBpHVpNI-orK8606K5oUSr5sv5LYvyuEHW3dymwVIDRYWUVxMITMp_st7Ee4PjD9nIQCzAeXHDcZ6c14jBQACPySjFKPkqeu5eiB0YfcYLQpvo0vnu6WEQ4XJnzNWWrV9JuOQ2AfWVeIc0D7fuK4ofXMRhTxAXm-btkqTrm0tBA"#;

    let icp_str = r#"{"v":"KERI10JSON0001b7_","t":"icp","d":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","s":"0","kt":"1","k":["DWow4n8Wxqf_UTvzoSnWOrxELM3ptd-mbtZC146khE4w"],"nt":"1","n":["EcjtYj92jg7qK_T1-5bWUlnBU6bdVWP-yMxBHjr_Quo8"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-AABAA0Dn5vYNWAz8uN1N9cCR-HfBQhDIhb-Crt_1unJY7KTAfz0iwa9FPWHFLTgvTkd0yUSw3AZuNc5Xbr-VMzQDhBw"#;
    let to_process: Vec<_> = [icp_str, rcps]
        .iter()
        .map(|event| parse_event_stream(event.as_bytes()).unwrap())
        .flatten()
        .collect();
    for msg in to_process {
        if let Message::Notice(msg) = msg {
            processor.process_notice(&msg).unwrap();
        }
    }

    let qry_str = r#"{"v":"KERI10JSON000104_","t":"qry","d":"ErXRrwRbUFylKDiuOp8a1wO2XPAY4KiMX4TzYWZ1iAGE","dt":"2022-03-21T11:42:58.123955+00:00","r":"ksn","rr":"","q":{"s":0,"i":"E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM","src":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"}}-VAj-HABE6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM-AABAAk-Hyv8gpUZNpPYDGJc5F5vrLNWlGM26523Sgb6tKN1CtP4QxUjEApJCRxfm9TN8oW2nQ40QVM_IuZlrly1eLBA"#;

    let parsed = parse_event_stream(qry_str.as_bytes()).unwrap();
    if let Message::Op(Op::Query(signed_query)) = parsed.get(0).unwrap().clone() {
        let r = process_signed_query(signed_query, &storage)?;

        if let ReplyType::Ksn(ksn) = r {
            assert_eq!(
                ksn.state.prefix,
                "E6OK2wFYp6x0Jx48xX0GCTwAzJUTWtYEvJSykVhtAnaM"
                    .parse()
                    .unwrap()
            );
            assert_eq!(ksn.state.sn, 0);
        } else {
            panic!("Wrong reply")
        }
    }

    Ok(())
}

#[cfg(feature = "oobi")]
#[test]
fn processs_oobi() -> Result<(), Error> {
    use keri::oobi::OobiManager;
    use tempfile::Builder;

    let oobi_rpy = r#"{"v":"KERI10JSON000116_","t":"rpy","d":"EZuWRhrNl9gNIck0BcLiPegTJTw3Ng_Hq3WTF8BOQ-sk","dt":"2022-04-12T08:27:47.009114+00:00","r":"/end/role/add","a":{"cid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","role":"controller","eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0Bke1uKEan_LNlP3e5huCO7zHEi50L18FB1-DdskAEyuehw9gMjNMhex73C9Yr0WlkP1B1-JjNIKDVm816zCgmCw"#;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let (processor, storage, oobi_manager) = (
        BasicProcessor::new(db.clone()),
        EventStorage::new(db.clone()),
        OobiManager::new(oobi_root.path()),
    );
    let events = parse_event_stream(oobi_rpy.as_bytes()).unwrap();
    for event in events {
        let res = process_message(event, &oobi_manager, &processor, &storage);
        assert!(res.is_ok())
    }
    Ok(())
}
