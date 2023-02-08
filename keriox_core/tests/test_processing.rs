use std::{sync::Arc, time::Duration};

use keri::{
    actor::{parse_event_stream, prelude::*},
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event_message::signed_event_message::Op,
    processor::{escrow::default_escrow_bus, event_storage::EventStorage},
};

#[test]
pub fn test_ksn_query() -> Result<(), Box<dyn std::error::Error>> {
    use keri::event_message::signed_event_message::Message;
    use tempfile::Builder;

    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path())?);

    let escrow_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);

    let (notification_bus, (_ooo_escrow, _ps_esrow, _pw_escrow, _)) =
        default_escrow_bus(db.clone(), escrow_db, Duration::from_secs(60));

    let (processor, storage) = (
        BasicProcessor::new(db.clone(), Some(notification_bus)),
        EventStorage::new(db),
    );
    // Process inception event and its receipts. To accept inception event it must be fully witnessed.
    let events_raw = r#"{"v":"KERI10JSON000159_","t":"icp","d":"ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_","i":"ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_","s":"0","kt":"1","k":["DDhKvndcqZlJNx-mtC_5eTy7UiuxOPVgAV3HsmofP2Ll"],"nt":"1","n":["EOOlrw-1jQHp8IfE1mfOb_ikXpHksVSyZ0RCnu5X0Rfg"],"bt":"0","b":["DNjeO6mfXSbrFFdk5UjDmioaho6ON0Sp6JMfhKz2jJF-"],"c":[],"a":[]}-AABAAD34oIVuxmLLKldRCzhfxR9hNg2SOMbOKZn1hp6D1OBmA6Hut6gSID21vFk50ost8_-VNbjHIQnHZ8WulUJ_yQL{"v":"KERI10JSON000091_","t":"rct","d":"ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_","i":"ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_","s":"0"}-CABDNjeO6mfXSbrFFdk5UjDmioaho6ON0Sp6JMfhKz2jJF-0BCTI8wy4v_Iyiyh4cSuG02R-K4GZHMXQVyC3yckpPpev0yWUiuera6q7ErDIQDLvjnMG5UuE2Ycw8-sxzeybicP"#;
    let to_process = parse_event_stream(events_raw.as_bytes())?;
    for msg in to_process {
        if let Message::Notice(msg) = msg {
            processor.process_notice(&msg).unwrap();
        }
    }

    let qry_str = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"ENp5aP1sEyT0tYa-Jz6sTlrhW82vp96_j5UKevVB7VEX","dt":"2022-10-25T11:40:27.023790+00:00","r":"ksn","rr":"","q":{"i":"ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_"}}-HABENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_-AABAABdEDGCtpvQl_zNlDMCnj9JwKHDKySapQRyzcAuo53DP7NPX5fl-GJYrfqXf3PPTF9tbxWWOUKaWurW5M1EVyIJ"#;

    let parsed = parse_event_stream(qry_str.as_bytes()).unwrap();
    if let Message::Op(Op::Query(signed_query)) = parsed.get(0).unwrap().clone() {
        let r = process_signed_query(signed_query, &storage)?;

        if let ReplyType::Ksn(ksn) = r {
            assert_eq!(
                ksn.state.prefix,
                "ENRc2DeK48BKJ3ST8mypvngVwEAxw9rZr_GPNP25TmQ_"
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

    let oobi_rpy = r#"{"v":"KERI10JSON000113_","t":"rpy","d":"EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpLZAkcoMkk","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y","role":"watcher","eid":"BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"}}-VAi-CABBLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y0BDa3HMDHpdGb9rQ1wsYmQdGMoeFrO2OguTUBXU6kvJjqb2ucmAka59hU9SC-z3YbRGuJchnBIA2N5Q9ja843OkG"#;
    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let (processor, storage, oobi_manager) = (
        BasicProcessor::new(db.clone(), None),
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
