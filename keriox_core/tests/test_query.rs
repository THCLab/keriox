#[cfg(feature = "query")]
mod test_query {
    use std::sync::Arc;

    use keri_core::{
        actor::{parse_event_stream, prelude::*},
        database::redb::RedbDatabase,
        event_message::signed_event_message::Op,
        processor::{
            escrow::{default_escrow_bus, EscrowConfig},
            event_storage::EventStorage,
        },
    };
    use tempfile::NamedTempFile;

    #[test]
    pub fn test_ksn_query() -> Result<(), Box<dyn std::error::Error>> {
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());

        let (notification_bus, _escrows) =
            default_escrow_bus(events_db.clone(), EscrowConfig::default(), None);

        let (processor, storage) = (
            BasicProcessor::new(events_db.clone(), Some(notification_bus)),
            EventStorage::new(events_db.clone()),
        );
        // Process the inception event. Its witness threshold is 0, so it is
        // accepted without receipts.
        let events_raw = r#"{"v":"KERI10JSON000159_","t":"icp","d":"EBlZM-G8xiZhrO84wyOnRZnmE1YgZ-c0P4ulJxyEDaDg","i":"EBlZM-G8xiZhrO84wyOnRZnmE1YgZ-c0P4ulJxyEDaDg","s":"0","kt":"1","k":["DCO2MXCd8igyoEspoWd6t2EFjstCMp4U_UhCaeY_5Vxg"],"nt":"1","n":["EJHDwL7IvPYy_osZWOYMOka1g4t3p4Ng73scbm8-uGeU"],"bt":"0","b":["BCvCgAszFuAJIJ_9dX2rGczwroS8eukGVOHoFxLScPZT"],"c":[],"a":[]}-KABAADwX0f-31KsZJahDvI-VhQalxm2uDBY9LVi81kTTv0pjDptikMypSF4mDc47TNxzzg5Hjx_V0QDDeXm_L9-yKMN"#;
        let to_process = parse_event_stream(events_raw.as_bytes())?;
        for msg in to_process {
            if let Message::Notice(msg) = msg {
                processor.process_notice(&msg).unwrap();
            }
        }

        let qry_str = r#"{"v":"KERI10JSON0000c9_","t":"qry","d":"EPqaYQCOyaO9SyJ5VoOOUn0m5OzAoQyvxyzVT7QWRY7X","dt":"2026-10-22T23:39:55.449099+00:00","r":"ksn","rr":"","q":{"i":"EBlZM-G8xiZhrO84wyOnRZnmE1YgZ-c0P4ulJxyEDaDg"}}-YABEBlZM-G8xiZhrO84wyOnRZnmE1YgZ-c0P4ulJxyEDaDg-KABAACvb6MDAg99BKM33nNE6u9lxFmA_q6dylPGJh9ctHODKQADVCOlO1ajZfRbhSsbjtw69j73ahHDAQPHP6dvO5cH"#;

        let parsed = parse_event_stream(qry_str.as_bytes()).unwrap();
        // let signed_query = parsed.get(0).unwrap().clone();
        // if let Message::Op(Op::Query(signed_query)) = parsed.get(0).unwrap().clone() {
        if let Message::Op(Op::Query(signed_query)) = parsed.get(0).unwrap().clone() {
            let r = process_signed_query(signed_query, &storage)?;

            if let ReplyType::Ksn(ksn) = r {
                assert_eq!(
                    ksn.state.prefix,
                    "EBlZM-G8xiZhrO84wyOnRZnmE1YgZ-c0P4ulJxyEDaDg"
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
}
