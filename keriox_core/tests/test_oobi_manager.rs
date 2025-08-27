#[cfg(feature = "oobi-manager")]
mod test_oobi_manager {
    use std::sync::Arc;

    use keri_core::{
        actor::{parse_event_stream, process_reply},
        database::redb::RedbDatabase,
        error::Error,
        event_message::signed_event_message::{Message, Op},
        processor::{basic_processor::BasicProcessor, event_storage::EventStorage},
    };
    use tempfile::NamedTempFile;
    #[test]
    fn processs_oobi() -> Result<(), Error> {
        use keri_core::oobi_manager::OobiManager;
        let oobi_rpy = r#"{"v":"KERI10JSON000113_","t":"rpy","d":"EFlkeg-NociMRXHSGBSqARxV5y7zuT5z-ZpLZAkcoMkk","dt":"2021-01-01T00:00:00.000000+00:00","r":"/end/role/add","a":{"cid":"BLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y","role":"watcher","eid":"BF6YSJGAtVNmq3b7dpBi04Q0YdqvTfsk9PFkkZaR8LRr"}}-VAi-CABBLK_YxcmK_sAsSW1CbNLJl_FA0gw0FKDuPr_xUwKcj7y0BDa3HMDHpdGb9rQ1wsYmQdGMoeFrO2OguTUBXU6kvJjqb2ucmAka59hU9SC-z3YbRGuJchnBIA2N5Q9ja843OkG"#;

        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let (processor, storage, oobi_manager) = (
            BasicProcessor::new(events_db.clone(), None),
            EventStorage::new(events_db.clone()),
            OobiManager::new(events_db.clone()),
        );
        let events = parse_event_stream(oobi_rpy.as_bytes()).unwrap();
        for event in events {
            match event {
                Message::Op(Op::Reply(rpy)) => {
                    let res = process_reply(rpy, &oobi_manager, &processor, &storage);
                    assert!(res.is_ok())
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
}
