use std::{
    convert::{TryFrom, TryInto},
    fs,
    sync::Arc,
    thread::{self, sleep},
    time::Duration,
};

use cesrox::{parse, parse_many, payload::parse_payload};
use tempfile::NamedTempFile;

use crate::{
    database::{
        escrow::EscrowDb, redb::RedbDatabase, sled::SledEventDatabase, EventDatabase,
        QueryParameters,
    },
    error::Error,
    event_message::{
        cesr_adapter::EventType,
        signed_event_message::{Message, Notice, SignedEventMessage},
    },
    prefix::IdentifierPrefix,
    processor::{
        basic_processor::BasicProcessor,
        escrow::{
            maybe_out_of_order_escrow::MaybeOutOfOrderEscrow,
            partially_witnessed_escrow::PartiallyWitnessedEscrow, PartiallySignedEscrow,
            TransReceiptsEscrow,
        },
        event_storage::EventStorage,
        notification::JustNotification,
        Processor,
    },
};

#[test]
fn test_process_transferable_receipt() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    // let (not_bus, _ooo_escrow) = default_escrow_bus(db.clone(), escrow_db);
    let events_db_path = NamedTempFile::new().unwrap();
    let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let mut event_processor = BasicProcessor::new(events_db.clone(), Arc::clone(&db), None);
    let event_storage = EventStorage::new(Arc::clone(&events_db), Arc::clone(&db));

    // Register transferable receipts escrow, to save and reprocess out of order receipts events
    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
    let trans_receipts_escrow = Arc::new(TransReceiptsEscrow::new(
        events_db.clone(),
        db.clone(),
        escrow_db,
        Duration::from_secs(10),
    ));
    event_processor.register_observer(
        trans_receipts_escrow.clone(),
        &[
            JustNotification::TransReceiptOutOfOrder,
            JustNotification::KeyEventAdded,
        ],
    )?;

    // Events and sigs are from keripy `test_direct_mode` test.
    // (keripy/tests/core/test_eventing.py)
    // Parse and process controller's inception event.
    let icp_raw = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"0","kt":"1","k":["DC8kCMHKrYZewclvG9vj1R1nSspiRwPi-ByqRwFuyq4i"],"nt":"1","n":["EBPlMwLJ5rSKWCaZq4bczEHLQvYX3P7cILmBzy0Pp4O4"],"bt":"0","b":[],"c":[],"a":[]}-AABAAAWQ0yBzzzVsOJPDkKzbDPzfYXEF5xmQgJSEKXcDO3XMVSL2DmDRYZV73huYX5BAsfzIhBXggKKAcGcEfT38R8L"#;
    let parsed = parse(icp_raw).unwrap().1;
    let icp = Message::try_from(parsed).unwrap();
    let controller_id =
        "EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL".parse::<IdentifierPrefix>()?;

    event_processor.process(&icp)?;
    let controller_id_state = event_storage.get_state(&controller_id);
    assert_eq!(controller_id_state.clone().unwrap().sn, 0);

    // Parse receipt of controller's inception event.
    let vrc_raw = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","i":"EJe_sKQb1otKrz6COIL8VFvBv3DEFvtKaVFGn1vm0IlL","s":"0"}-FABEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz0AAAAAAAAAAAAAAAAAAAAAAAEAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz-AABAAD-iI61odpZQjzm0fN9ZATjHx-KjQ9W3-CIlvhowwUaPC5KnQAIGYFuWJyRgAQalYVSEWoyMK2id_ONTFUE-NcF"#;
    let parsed = parse(vrc_raw).unwrap().1;
    let rcp = Message::try_from(parsed).unwrap();

    event_processor.process(&rcp.clone())?;
    // Validator not yet in db. Event should be escrowed.
    let validator_id = "EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz".parse()?;
    assert_eq!(
        trans_receipts_escrow
            .escrowed_trans_receipts
            .get(&validator_id)
            .unwrap()
            .count(),
        1
    );

    // Parse and process validator's inception event.
    let val_icp_raw = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz","i":"EAzjKx3hSVJArKpIOVt2KfTRjq8st22hL25Ho9vnNodz","s":"0","kt":"1","k":["BF5b1hKlY38RoAhR7G8CExP4qjHFvbHx25Drp5Jj2j4p"],"nt":"1","n":["ECoxJfQH0GUrlDKoC3U-neGY1CJib7VyZGh6QhdJtWoT"],"bt":"0","b":[],"c":[],"a":[]}-AABAACOKLyxKvQyy_TvkfQffGnk-p0cc1H11dpxV8gbxvYGm5kfvqPerlorqD21hGRAqvyFQJ967Y8lFl_dxTaal2cA"#;
    let parsed = parse(val_icp_raw).unwrap().1;
    let val_icp = Message::try_from(parsed).unwrap();

    event_processor.process(&val_icp)?;
    let validator_id_state = event_storage.get_state(&validator_id);
    assert_eq!(validator_id_state.unwrap().sn, 0);

    // Escrowed receipt should be removed and accepted
    assert_eq!(
        trans_receipts_escrow
            .escrowed_trans_receipts
            .get(&validator_id)
            .unwrap()
            .count(),
        0
    );
    assert_eq!(
        event_storage
            .events_db
            .get_receipts_t(QueryParameters::BySn {
                id: controller_id.clone(),
                sn: 0
            })
            .unwrap()
            .count(),
        1
    );

    let id_state = EventStorage::new(events_db.clone(), Arc::clone(&db)).get_state(&controller_id);
    // Controller's state shouldn't change after processing receipt.
    assert_eq!(controller_id_state, id_state);

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_reply_escrow() -> Result<(), Error> {
    use cesrox::parse_many;
    use tempfile::Builder;

    use crate::{
        event_message::signed_event_message::Op,
        processor::{escrow::ReplyEscrow, notification::JustNotification, Processor},
    };

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let events_db_path = NamedTempFile::new().unwrap();
    let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let mut event_processor = BasicProcessor::new(events_db.clone(), Arc::clone(&db), None);
    event_processor.register_observer(
        Arc::new(ReplyEscrow::new(db.clone(), events_db.clone())),
        &[
            JustNotification::KeyEventAdded,
            #[cfg(feature = "query")]
            JustNotification::KsnOutOfOrder,
        ],
    )?;

    let identifier: IdentifierPrefix = "EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH".parse()?;

    let kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAArkDBeflIAo4kBsKnc754XHJvdLnf04iq-noTFEJkbv2MeIGZtx6lIfJPmRSEmFMUkFW4otRrMeBGQ0-nlhHEE-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EHZks1BQ_ieuzASY7VoZNIOgIfnlE-SZJzO3OP_Wf3zM","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"1","p":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","kt":"1","k":["DMm-PHnlVVw-yQGqxxQFH3ynIGBrwkOCll9NJsszS4M1"],"nt":"1","n":["EGDpG5Ca3-vx-0O_rCXo44CG9VfjvDM8kXZlXt5TRGqq"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAB49lUrFy86023zwry5pLz3_stNBPLU2Zoj2HO02W-J-fXvA9EL7BOpuVjEdhPHz1KbRWOKljI8yY3PZR3PyiMG-EAB0AAAAAAAAAAAAAAAAAAAAAAB1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"2","p":"EHZks1BQ_ieuzASY7VoZNIOgIfnlE-SZJzO3OP_Wf3zM","kt":"1","k":["DMjdd0iohdRbFaFUeQuK_9eSSS1AcQVwZpJXg-QGFqZX"],"nt":"1","n":["ECDBhT8ht1Z2WFeC6C_7sCAPkduj3DDjEz2cxI_RSo-I"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAtK2_idK0_YfBrswOvbjBFWtjTZ5XRRU42HC7eoph_gi67BCeTaMBUBKyx5LZYnAG3GzOl5Xj-CXkvzSlwJ10K-EAB0AAAAAAAAAAAAAAAAAAAAAAC1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"3","p":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","kt":"1","k":["DK3AM_4Jg07liB5_5jkA3kiv2iSEYsOSDMzw-4oMxA29"],"nt":"1","n":["EGdk-oXzuVUatJYeIuai9wlUJ0ulVUTrb9w0LPPuuyB0"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAMxebsLh1V2NIHJl0diSC242MSg5TNSbtgjZPuf34adjV9rs6B73pWyt-TmRWMIY-me9-pg3eN0p4wQsyBWIEC-EAB0AAAAAAAAAAAAAAAAAAAAAAD1AAG2021-01-01T00c00c00d000000p00c00"#;

    let parsed = parse_many(kel.as_bytes()).unwrap().1;
    let kel_events = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let rest_of_kel = r#"{"v":"KERI10JSON000160_","t":"rot","d":"EHVjHgDO5Gm7VJX1_0pfajNdsr5yMWxeu8jTBDFM3Hxx","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"4","p":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","kt":"1","k":["DHCf_d5wepRUYrkwii7D9D_ix9m8YJ1u6c7Kf4vChB2-"],"nt":"1","n":["EDnPDsp4HhTExdfBa_ZKoW9wwVsO8SXQnDAikGP2wbcX"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAp185sbBdPawKcVHO_8mrMIYtAG5mKNlQWWvCIFVlIszQcge3FAEfYq4cw9Gh_tY82PBPLBPlgXYjLYnRxXQkD-EAB0AAAAAAAAAAAAAAAAAAAAAAE1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EFltRrVgHygpUoAIpyiYHUe0Zt8-lPQ20iNk2fA0CGnB","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"5","p":"EHVjHgDO5Gm7VJX1_0pfajNdsr5yMWxeu8jTBDFM3Hxx","kt":"1","k":["DMOFqHNTbaOrzXv6Hs6d08Nd_mLo7wiH-888vFGtFWmV"],"nt":"1","n":["ECYVu54u3AXOkOZjf2RZnbeRxbu10vBW85rZTgXKcoVH"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAAERG7cm3_SLovALeBeadaIzCh55ul_Mj3mp4UNdzvmdbBbGMDTxrkEVHpM25BOROuhIRKWUdw6yVFubbKgl7wI-EAB0AAAAAAAAAAAAAAAAAAAAAAF1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EGs1eJFrFrcenQouDUk57AA5lYs8E-xOVcLPu0me-gyS","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"6","p":"EFltRrVgHygpUoAIpyiYHUe0Zt8-lPQ20iNk2fA0CGnB","kt":"1","k":["DIxsQo0QFWhYlX34UHDw39OG4nIr5tky9S5Jwi97o7-d"],"nt":"1","n":["EJyVykl3kJen1vWe9MkOKNQ6DN6h16hAcqU7h77MSkpn"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAADkk6omMn4qARRuu6EJlSqvkEcZlSRxF9wDMuJLf31k0U7XBgFaYMJA50V7yUI46GGbF7t3x72NZxiM0EhzeqMB-EAB0AAAAAAAAAAAAAAAAAAAAAAG1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"7","p":"EGs1eJFrFrcenQouDUk57AA5lYs8E-xOVcLPu0me-gyS","kt":"1","k":["DME53BRS5KnXzsfYqT8I2DCfl6nMOrlYBN_Fm3wIh9M0"],"nt":"1","n":["EKsCb2J8R1gnygI5QiYIJ67CJYrXx-uZ_iM0yITQYDV9"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAB6IYTjz7nE_44ttVWLyNsIxjMOUs8mx1_L-XiD1Hu61W8efpvlf2cpZWrhmFuNtAxGTyFpfXL9dwjaC0cQTsUH-EAB0AAAAAAAAAAAAAAAAAAAAAAH1AAG2021-01-01T00c00c00d000000p00c00{"v":"KERI10JSON000160_","t":"rot","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"8","p":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","kt":"1","k":["DDnnUcnyEHuGfhjUpW4APLcSCsseC4trSdUtGIcu5dk_"],"nt":"1","n":["EEH-Nd5uWnAjXzX1mwBsz6WZWbCbGZBZIuurBl2r8TPn"],"bt":"0","br":[],"ba":[],"a":[]}-VAn-AABAAC5QaZ2nCtxB9-RQ68LxbKABJ_QP7aFbAVnAPW4usBCiNbTL6DDzSI1Z3ykh6RPczk0HYfRW39kbtMWsIPHQ1MJ-EAB0AAAAAAAAAAAAAAAAAAAAAAI1AAG2021-01-01T00c00c00d000000p00c00"#;
    let parsed = parse_many(rest_of_kel.as_bytes()).unwrap().1;
    let rest_of_kel = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let old_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EJjB0S6SaAA1ymaO0cXVmv5kJagHVVUVpxD6q5_jrcgP","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":{"v":"KERI10JSON0001e2_","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"3","p":"ECg9CiC6qW-Y8DF-TByP0x4tG_OvPkAtKSZuZU8ZiXYT","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DK3AM_4Jg07liB5_5jkA3kiv2iSEYsOSDMzw-4oMxA29"],"nt":"1","n":["EGdk-oXzuVUatJYeIuai9wlUJ0ulVUTrb9w0LPPuuyB0"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs","br":[],"ba":[]},"di":""}}-VA0-FABEA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH0AAAAAAAAAAAAAAAAAAAAAADEHnhq9u8zdNJB38yaY3r7G73LrnJsPakgSjJFk6vSxUs-AABAADfyYgxdTg4vvKcbCHaog79P3KVJJX_bYMZOuOobmLM9uWLmTVHFvFB36-hS062DfCsCyBF0tmODSlmVY-TksUC"#;
    let parsed = parse(old_rpy.as_bytes()).unwrap().1;
    let deserialized_old_rpy = Message::try_from(parsed).unwrap();

    let new_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EJX7EebLoW8VTVvO3iPuFGzy38BU6OEEsRR9nFjzgeL6","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","a":{"v":"KERI10JSON0001e2_","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"8","p":"ECfNpyS_AJmk_tbcQfbMQAcXUZHzv_3Hb6OAxp7EMy09","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","f":"8","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DDnnUcnyEHuGfhjUpW4APLcSCsseC4trSdUtGIcu5dk_"],"nt":"1","n":["EEH-Nd5uWnAjXzX1mwBsz6WZWbCbGZBZIuurBl2r8TPn"],"bt":"0","b":[],"c":[],"ee":{"s":"8","d":"EJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7","br":[],"ba":[]},"di":""}}-VA0-FABEA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH0AAAAAAAAAAAAAAAAAAAAAAIEJ8T_WbwJfv7xYI6PforMwweAT0o7i7c6rRNhdkqOyQ7-AABAABuq6TXP5ZHc62y8NxNnKJjyJ1b4Nc1Mfu4ZKzg_47kbRyBriC9k7vnuidpIOfjUE7tnseaY5p6Gyr5qULXJWEK"#;
    let parsed = parse(new_rpy.as_bytes()).unwrap().1;
    let deserialized_new_rpy = Message::try_from(parsed).unwrap();

    // Try to process out of order reply
    event_processor
        .process(&deserialized_old_rpy.clone())
        .unwrap();

    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 1);

    let accepted_rpys = db.get_accepted_replys(&identifier);
    assert!(accepted_rpys.is_none());

    // process kel events and update escrow
    // reply event should be unescrowed and save as accepted
    kel_events.for_each(|ev| {
        event_processor.process(&ev).unwrap();
    });

    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let accepted_rpys = db.get_accepted_replys(&identifier);
    assert_eq!(accepted_rpys.unwrap().collect::<Vec<_>>().len(), 1);

    // Try to process new out of order reply
    // reply event should be escrowed, accepted reply shouldn't change
    event_processor.process(&deserialized_new_rpy.clone())?;
    let mut escrow = db.get_escrowed_replys(&identifier).unwrap();
    assert_eq!(
        Message::Op(Op::Reply(escrow.next().unwrap())),
        deserialized_new_rpy
    );
    assert!(escrow.next().is_none());

    let mut accepted_rpys = db.get_accepted_replys(&identifier).unwrap();
    assert_eq!(
        Message::Op(Op::Reply(accepted_rpys.next().unwrap())),
        deserialized_old_rpy
    );
    assert!(accepted_rpys.next().is_none());

    // process rest of kel and update escrow
    // reply event should be unescrowed and save as accepted
    rest_of_kel.for_each(|ev| {
        event_processor.process(&ev).unwrap();
    });

    let escrow = db.get_escrowed_replys(&identifier);
    assert_eq!(escrow.unwrap().collect::<Vec<_>>().len(), 0);

    let mut accepted_rpys = db.get_accepted_replys(&identifier).unwrap();

    assert_eq!(
        Message::Op(Op::Reply(accepted_rpys.next().unwrap())),
        deserialized_new_rpy
    );
    assert!(accepted_rpys.next().is_none());

    Ok(())
}

#[test]
fn test_escrow_missing_signatures() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"0","kt":"1","k":["DJPJ89wKDXMW9Mrg18nZdqp37gCEXuCrTojzVXhHwGT6"],"nt":"1","n":["ENey4-IfkllvEDtKtlFXlr0bhAFFfHQp-n6n2MYEick0"],"bt":"0","b":["DHEOrU8GRgLhjFxz-72koNrxJ5Gyj57B_ZGmYjqbOf4W"],"c":[],"a":[]}-AABAACuardPTXF2hZVuFkhbD6-r84g6p3RoZl_nJRVH6kEOmqxZpw1fj37b7s8LJ649TecIu4Pxb-A2Lu05AptmlBkO{"v":"KERI10JSON000160_","t":"rot","d":"EIBUvQrJbIHvkzQt1hZs1-chTR7FELwknEhQKTS-ku_e","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"1","p":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","kt":"1","k":["DGuK-ColPgPuH_FCZopzjQAoMN2aNzk3rioNewx1_2El"],"nt":"1","n":["EB78ym8c7Z86gmZWZawXYCk5uMy8H6fC5iPdd3d7VPvk"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAyw89UHMWvXFyDxJva0uCslgPadFzdNnhFzVjaCvvmV0l6vtXKln1wiy382QbOb69u9DuPgIQUdXLIW9xMJAMI"#;
    let event_without_signature_str = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ENSAcKy3MKyQoYJtXVaNiWHHcFSKwnnN0X_x9-i70q0N","i":"EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A","s":"2","p":"EIBUvQrJbIHvkzQt1hZs1-chTR7FELwknEhQKTS-ku_e","a":[]}-AABAAC-Oy9w2O16tEzQfIW1TjExYyRbQyBeuc6Etrkdc-QIN_wS3iyw_LYqLI6Zmp34UBkdNv0ZLEjTTcX8dyuJVq0M"#;
    let mut kell = parse_many(kel)
        .unwrap()
        .1
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let (event_without_signatures, _event) = match parse_payload(event_without_signature_str)
        .unwrap()
        .1
        .try_into()?
    {
        EventType::KeyEvent(event) => (
            Message::Notice(Notice::Event(SignedEventMessage {
                event_message: event.clone(),
                signatures: vec![],
                witness_receipts: None,
                delegator_seal: None,
            })),
            event,
        ),
        _ => unreachable!(),
    };

    use tempfile::Builder;

    let (processor, storage, ooo_escrow, ps_escrow) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        let mut processor = BasicProcessor::new(events_db.clone(), witness_db.clone(), None);

        // Register out of order escrow, to save and reprocess out of order events
        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);

        // Register out of order escrow, to save and reprocess out of order events
        let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
            events_db.clone(),
            witness_db.clone(),
            Duration::from_secs(10),
        ));
        processor.register_observer(
            ooo_escrow.clone(),
            &[
                JustNotification::OutOfOrder,
                JustNotification::KeyEventAdded,
            ],
        )?;

        let ps_escrow = Arc::new(PartiallySignedEscrow::new(
            events_db.clone(),
            witness_db.clone(),
            escrow_db.clone(),
            Duration::from_secs(10),
        ));
        processor.register_observer(
            ps_escrow.clone(),
            &[
                JustNotification::PartiallySigned,
                JustNotification::KeyEventAdded,
            ],
        )?;

        std::fs::create_dir_all(path).unwrap();
        (
            BasicProcessor::new(events_db.clone(), witness_db.clone(), None),
            EventStorage::new(events_db.clone(), witness_db.clone()),
            ooo_escrow,
            ps_escrow,
        )
    };
    let id: IdentifierPrefix = "EMTMYJQ3Eaq8YjG94c_GGvihe5cW8vFFXX2PezAwrn2A".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().sn, 0);

    // Process out of order event without signatures
    processor.process(&event_without_signatures)?;

    assert!(ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap()
        .next()
        .is_none(),);

    // try to process unsigned event, but in order
    processor.process(&ev2)?;
    processor.process(&event_without_signatures)?;

    // check partially signed escrow
    assert!(ps_escrow.escrowed_partially_signed.get(&id).is_none());

    Ok(())
}

#[test]
fn test_partially_sign_escrow() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage, ps_escrow) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let sled_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let mut processor = BasicProcessor::new(events_db.clone(), sled_db.clone(), None);

        // Register partially signed escrow, to save and reprocess partially signed events
        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
        let ps_escrow = Arc::new(PartiallySignedEscrow::new(
            events_db.clone(),
            sled_db.clone(),
            escrow_db,
            Duration::from_secs(10),
        ));
        processor.register_observer(ps_escrow.clone(), &[JustNotification::PartiallySigned])?;

        (
            processor,
            EventStorage::new(events_db.clone(), sled_db.clone()),
            ps_escrow,
        )
    };

    let parse_messagee = |raw_event| {
        let parsed = parse(raw_event).unwrap().1;
        Message::try_from(parsed).unwrap()
    };

    let id: IdentifierPrefix = "EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_".parse()?;
    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtphYLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],"a":[]}-AABAAC3xWTpnv14_khneBqDlrK7JHPUoHNJhWMIXzXbK80RVyEYV7iMsWaAXfepkRsyELBLd25atAtE3iLeDn1I-gUM'"#;
    let icp_first_sig = parse_messagee(icp_raw);

    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtphYLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],"a":[]}-AABACAwNb8Lj-vxJYMi_vIH-ETGG0dVfqIk4ihrQvV1iL1_07eWfu4BwRYCPCZDo0F0Xbkz0DP4xXVfChR-lFd2npUG"#;
    let icp_second_sig = parse_messagee(icp_raw);

    processor.process(&icp_first_sig)?;
    let icp_event = if let Message::Notice(Notice::Event(ev)) = icp_first_sig.clone() {
        Some(ev.event_message)
    } else {
        None
    }
    .unwrap();

    let mut escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(icp_first_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id), None);

    // check escrow
    assert_eq!(
        ps_escrow
            .get_partially_signed_for_event(icp_event.clone())
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    processor.process(&icp_second_sig)?;

    // Now event is fully signed, check if escrow is emty
    assert_eq!(
        ps_escrow
            .get_partially_signed_for_event(icp_event.clone())
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert!(storage.get_state(&id).is_some());

    let ixn = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"1","p":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","a":[]}-AABABC3seofRQNJPKgqXy6Y2N_VsewM1QkG7Y1hfIOosAKW8EdB9nUvqofUhOdSuH2LUzV3S4uenFe-G8EP_VhQaLAH"#;
    let ixn_first_sig = parse_messagee(ixn);

    let ixn2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"1","p":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","a":[]}-AABAAAsZ-qmrZIreJgAd34xZEb_mHTc7tjgwMzMbd31sRyt8a1osduDv_uzeqWiicSauNyiehjfPjeJa1ZJfOGBgbEP"#;
    let ixn_second_sig = parse_messagee(ixn2);

    let ixn_event = if let Message::Notice(Notice::Event(ev)) = ixn_first_sig.clone() {
        Some(ev.event_message)
    } else {
        None
    }
    .unwrap();

    processor.process(&ixn_first_sig)?;

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap().sn, 0);

    // check escrow
    assert_eq!(
        ps_escrow
            .escrowed_partially_signed
            .get_all()
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    processor.process(&ixn_second_sig)?;

    // Now event is fully signed, check if escrow is empty
    assert_eq!(
        ps_escrow
            .get_partially_signed_for_event(ixn_event)
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert_eq!(storage.get_state(&id).unwrap().sn, 1);

    let rot = parse_messagee(br#"{"v":"KERI10JSON0002a6_","t":"rot","d":"EBV201a_Q2aMRPB2JlpTybBBO4Osp7o1-jRvSwayYFmy","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"2","p":"EODgCVSGS9S8ZaOr89HKDP_Zll21C8zbUBjbBU1HjGEk","kt":["1/2","1/2","1/2"],"k":["DHqJ2DNmypwMKelWXLgl3V-9pDRcOenM5Wf03O1xx1Ri","DEIISiMvtnaPTpMHkoGs4d0JdbwjreW53OUBfMedLUaF","DDQFJ_uXcZum_DY6NNTtI5UrTEQo6PRWEANpn6hVtfyQ"],"nt":[["1/2","1/2","1/2"],["1","1"]],"n":["EJsp5uWsQOsioYA16kbCZW9HPMr0rEaU4NUvfm6QTYd2","EFxT53mK2-1sAnh8VcLEL1HowQp0t84dfIWRaju5Ef61","EETqITKVCCpOS6aDPiZFJOSWll2i39xaFQkfAYsG18I_","EGGvSfHct9RLnwIMMkNrG7I0bRYO1uoUnP4QbnDFzBI6","ELTnTK-3KiF4zvY9WC0ZJjmFm8NFacQtuNiA8KuQkHQe"],"bt":"0","br":[],"ba":[],"a":[]}-AADAACj5KQr7VHyjvkBETGvqTk_lt2w0-oEVIpO_8acwJNygvJe1-ZsgcK02yBwHJFJ7N-qemGaDRsIxFnuJ3ya3TwAABDu4EVUGhvMWjdMhMgdJ-D_XapyM4lnGbaLKhjc7ndi39LCq-Ap9C4flibBVbqYpbwSyheHRYiyUythE5sks2kEACAkF7H6pJS_-aLAkCDVEFI4hK6aqMojyf--JFHtqVgG1mloIpeDQATu6DODSxv8zTZHwOaJwSERMk3fd6eVXIgG"#);

    processor.process(&rot)?;
    // assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 2);
    Ok(())
}

#[ignore]
#[test]
fn test_out_of_order_cleanup() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"0","kt":"1","k":["DODv7KGqEEhAP7-VYXzZvNi5wmgEB8w5y6HLUQL08PNh"],"nt":"1","n":["ECo41Mn5wku-tQd7L4Hp65KhaX1KkdTtSY_NXx4rQphS"],"bt":"0","b":["DPOIlcZk_GLVCVtG7KLbDQa2a5drXGt09wpaeY93G--1"],"c":[],"a":[]}-AABAADtEDd5x0DRfSlGl99G2V3aiJQlILTMG8LHNbG6V3ticL8r1vMK8-nmhZBhZglI06mVChxc-EkgqWPzPlI2rAwD{"v":"KERI10JSON000160_","t":"rot","d":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"1","p":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","kt":"1","k":["DIgRd-GK29iB-G7tao3-BCdMbUCATveeMrzivmmmM_Nf"],"nt":"1","n":["EBrEok_A-yJGpR9GH_ktdd11x3UR0cHaCg0nzAnYLgGj"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADLgLBVFeCOP8t-sxOWKif-JbQ-PnOz0W7aZCuLPOUEri-OdGXjOV2d3y6-R_SsS2U3toE3TNVJ9UyO5NhBSkkO{"v":"KERI10JSON000160_","t":"rot","d":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"2","p":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","kt":"1","k":["DGx72gYpAdz0N3br4blkVRRoIASdcBTJaqtLnGI6PXHV"],"nt":"1","n":["EMEVqKOHmF9juqQSmphqjnP24tT__JILJJ2Z4u9QKSUn"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAHF__vhEKj4kn1uW0fdBRS75nyG3uvJuEfcOdnx4sfy2vNirkDLkm6WGluUVDfQ7y9_b2TIaIHLfAoBefjNBkF{"v":"KERI10JSON000160_","t":"rot","d":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"3","p":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","kt":"1","k":["DFXuPGU9uFziSr3uQuDo7yKJFmcyURvTq8YOfLfNHf6r"],"nt":"1","n":["EO3OeLeP4Ux570nxE0cuK76Bn0I2NAyA1artuMiyASJf"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAXiKK5er1d8dlAorz6SVhp6xs33eoEKSn2JZrrUHTFZz4xjIa_Ectg9Jyvs12JkdjkNf3VUQ2GMsnfgBpIkXMB{"v":"KERI10JSON000160_","t":"rot","d":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"4","p":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","kt":"1","k":["DHkJs10SLaBPMBsPx8X6x4TozQMM8OuAzgj681jYSckq"],"nt":"1","n":["ELRF262pZpt8-UiEX5TSsCFiZ1NmRHkvHIq-M6mFKDw_"],"bt":"0","br":[],"ba":[],"a":[]}-AABAACx23xFm12mxnmA413AJCGK67SF5OHb6hlz6qbZjyWbkAqtmqmo2_SRFHtbSFpZ5yIVObSf_F9yr8sRQ-_pJg0F{"v":"KERI10JSON000160_","t":"rot","d":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"5","p":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","kt":"1","k":["DOFD9XUnKnAUyn0QjYq0BouHyYjvmHN7T2nnVaxr7VHz"],"nt":"1","n":["EFz-ndoE5OXjvD0-UdQAzepB8zpnfk44HN2h8aWmdnKB"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABKlwj4nLkk8q-1YhxA-NjTJCw6AiqyopKvp-MJgx-FKzgZecMmtGm3q5SLImR8P0evrVGL8-DvI-kF9FzYN5YP{"v":"KERI10JSON000160_","t":"rot","d":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"6","p":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","kt":"1","k":["DMrq2ktTKWxE5jjhDKDOz1T8a4R0ZGsikc7M-p5k-Rzp"],"nt":"1","n":["EKw6XLOELmjxU-N_EDuUQ7v1XfodiBVyf2nU2zaSIe05"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABzuuhSMYnxQVJ-K2lJP2WOfUP-oiQAp1Dm2685U-s-91bQovUHAoMoVFWcq0FnxC8W7rQHLXw-Wgt_-lo34u4H{"v":"KERI10JSON000160_","t":"rot","d":"EBOeYHB245lnMJY4or8FvfCaoYlwMVwE5Hr49VE6uXK8","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"7","p":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","kt":"1","k":["DApxTJjlbWOgHIMXR_qrryjCIlLFPqnaSRo2M1FFmp4I"],"nt":"1","n":["EOdAKz4CYF6RFZzs_Chyih7QRgcfcZaJ_G02Y-4lrfHg"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAmR-tO3N1b7b2ZCZmlaSYmQbgHE0T9wZANzXdezQ2b9XPS0RWJcMfHCtpn3qj0Jxhhij1OfMGPSqtshVtEXsYC"#;
    let mut kell = parse_many(kel)
        .unwrap()
        .1
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let ev3 = kell.next().unwrap();
    let ev4 = kell.next().unwrap();
    let _ev5 = kell.next().unwrap();

    use tempfile::Builder;

    let (processor, storage, ooo_escrow) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let sled_db = Arc::new(SledEventDatabase::new(path).unwrap());
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let mut processor = BasicProcessor::new(events_db.clone(), sled_db.clone(), None);

        // Register out of order escrow, to save and reprocess out of order events
        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
        let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
            events_db.clone(),
            sled_db.clone(),
            Duration::from_secs(1),
        ));
        processor.register_observer(
            ooo_escrow.clone(),
            &[
                JustNotification::KeyEventAdded,
                JustNotification::OutOfOrder,
            ],
        )?;

        std::fs::create_dir_all(path).unwrap();
        (
            processor,
            EventStorage::new(events_db.clone(), sled_db.clone()),
            ooo_escrow,
        )
    };
    let id: IdentifierPrefix = "EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().sn, 0);

    // Process out of order event and check escrow.
    processor.process(&ev4.clone())?;
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    // Process one more out of order event.
    processor.process(&ev3.clone())?;

    // Wait until escrowed events become stale.
    thread::sleep(Duration::from_secs(1));

    // Process inorder missing event.
    processor.process(&ev2.clone())?;

    // Escrow should be empty
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap();
    assert!(escrowed.next().is_none());

    // Stale events shouldn't be save in the kel.
    assert_eq!(storage.get_state(&id).unwrap().sn, 1);

    // Process out of order events once again and check escrow.
    processor.process(&ev4.clone())?;
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap();

    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    // Process inorder missing event.
    processor.process(&ev3.clone())?;

    // Escrow should be empty
    let mut escrowed = ooo_escrow
        .escrowed_out_of_order
        .get_from_sn(&id, 0)
        .unwrap();
    assert!(escrowed.next().is_none());

    // Events should be accepted, they're not stale..
    assert_eq!(storage.get_state(&id).unwrap().sn, 3);

    Ok(())
}

#[test]
fn test_partially_sign_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage, ps_escrow) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let mut processor = BasicProcessor::new(events_db.clone(), witness_db.clone(), None);

        // Register partially signed escrow, to save and reprocess partially signed events
        let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
        let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
        let ps_escrow = Arc::new(PartiallySignedEscrow::new(
            events_db.clone(),
            witness_db.clone(),
            escrow_db,
            Duration::from_secs(1),
        ));
        processor.register_observer(ps_escrow.clone(), &[JustNotification::PartiallySigned])?;

        (
            processor,
            EventStorage::new(events_db, witness_db.clone()),
            ps_escrow,
        )
    };

    let parse_messagee = |raw_event| {
        let parsed = parse(raw_event).unwrap().1;
        Message::try_from(parsed).unwrap()
    };

    let id: IdentifierPrefix = "EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M".parse()?;
    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],"a":[]}-AABAAjCyfd63fzueQfpOHGgSl4YvEXsc3IYpdlvXDKfpbicV8pGj2v-TWBDyFqkzIdB7hMhG1iR3IeS7vy3a3catGDg"#;
    let icp_first_sig = parse_messagee(icp_raw);

    let icp_raw = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],"a":[]}-AABACJz5biC59pvOpb3aUadlNr_BZb-laG1zgX7FtO5Q0M_HPJObtlhVtUghTBythEb8FpoLze8WnEWUayJnpLsYjAA"#;
    let icp_second_sig = parse_messagee(icp_raw);

    processor.process(&icp_first_sig)?;
    let icp_event = if let Message::Notice(Notice::Event(ev)) = icp_first_sig.clone() {
        Some(ev.event_message)
    } else {
        None
    }
    .unwrap();

    let mut escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(icp_first_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id), None);

    // Wait until escrowed events become stale.
    thread::sleep(Duration::from_secs(1));

    // Check if stale event was removed
    let mut escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert!(escrowed.next().is_none());

    // Proces the same event with another signature
    processor.process(&icp_second_sig)?;

    // check escrow
    let mut escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert_eq!(
        escrowed.next().map(|e| Message::Notice(Notice::Event(e))),
        Some(icp_second_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id), None);

    // Proces the same event with another signature
    processor.process(&icp_first_sig)?;

    Ok(())
}

#[ignore]
#[test]
pub fn test_partially_witnessed_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let events_db_path = NamedTempFile::new().unwrap();
    let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
    let mut event_processor = BasicProcessor::new(events_db.clone(), Arc::clone(&db), None);
    let event_storage = EventStorage::new(Arc::clone(&events_db), Arc::clone(&db));
    // Register not fully witnessed escrow, to save and reprocess events
    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
    let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        events_db.clone(),
        db.clone(),
        escrow_db,
        Duration::from_secs(1),
    ));
    event_processor.register_observer(
        partially_witnessed_escrow.clone(),
        &[
            JustNotification::PartiallyWitnessed,
            JustNotification::ReceiptOutOfOrder,
        ],
    )?;

    // check if receipt was escrowed
    let id: IdentifierPrefix = "E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
        .parse()
        .unwrap();

    // process icp event without processing receipts.
    let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0","kt":"2","k":["DLQ_T1HC_zZU5b3NsYhCQUX0c9GwyZW7U8pzkKTcFSod","DMW_TkkFsaufVLI0bYWjT7U8zZ_FV7PEiRF3W8RVGfpQ","DJEBW__ddS11UGhY_gofa4_PUE6SGU9wHFfk43AYW1zs"],"nt":"2","n":["EMBt6FEXUuQ02zCXVQicX2W60mmNy8VLiKUlokSf75WZ","EDTF0ZjY5ANPsHIONhplNVDOUEo5aQY9TiDTT3lm0JN6","EKw8rv7Uiugd6r7Zydvg6vY8MOQTOZtP43FodCH88hxk"],"bt":"2","b":["BN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev","BHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui","BJYw25nTX2-tyjqRleJpjysMsqdzsw7Ec6Ta3S9QUULb"],"c":[],"a":[]}-AADAABkmPJEhi5Pr8f-F4FEiBxU-5DF_Ff1LcyyYaOimqlPxs13RJWABWHx_NLQQ8L5O-pGW_zQ7dOWLP098IPoNFcJABAt-w_ejAVim4DrnqFQtZTwtoOqJrsvA1SWRvO-wu_FdyZDtcGhucP4Rl01irWx8MZlrCuY9QnftssqYcBTWBYOACAKMyHHcQ3htd4_NZwzBAUGgc0SxDdzeDvVeZa4g3iVfK4w0BMAOav2ebH8rcW6WoxsQcNyDHjkfYNTM4KNv50I"#;
    let parsed_icp = parse(icp_raw).unwrap().1;
    let icp_msg = Message::try_from(parsed_icp).unwrap();
    event_processor.process(&icp_msg.clone())?;

    let state = event_storage.get_state(&id);
    assert_eq!(state, None);

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
    let parsed_rcp = parse(receipt0_0).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if icp is in escrow
    let mut esc = partially_witnessed_escrow
        .escrowed_partially_witnessed
        .get_from_sn(&id, 0)
        .unwrap();
    assert_eq!(icp_msg, Message::Notice(Notice::Event(esc.next().unwrap())));
    assert!(esc.next().is_none());

    // let mut esc = partially_witnessed_escrow
    //     .escrowed_nontranferable_receipts
    //     .get_all()
    //     .unwrap();
    // assert_eq!(
    //     rcp_msg,
    //     Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
    // );
    // assert!(esc.next().is_none());

    // let state = event_storage.get_state(&id);
    // assert_eq!(state, None);

    // // Wait until escrowed events become stale.
    // sleep(Duration::from_secs(1));

    // // check if icp still in escrow
    // let mut esc = partially_witnessed_escrow
    //     .escrowed_partially_witnessed
    //     .get_all()
    //     .unwrap();
    // assert!(esc.next().is_none());

    // check if event was accepted into kel
    let state = event_storage.get_state(&id);
    assert_eq!(state, None);

    Ok(())
}

// #[test]
// pub fn test_nt_receipt_escrow_cleanup() -> Result<(), Error> {
//     use tempfile::Builder;

//     // Create test db and event processor.
//     // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
//     let root = Builder::new().prefix("test-db").tempdir().unwrap();
//     fs::create_dir_all(root.path()).unwrap();
//     let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
//     let events_db_path = NamedTempFile::new().unwrap();
//     let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
//     let mut event_processor = BasicProcessor::new(events_db.clone(), Arc::clone(&db), None);
//     let event_storage = EventStorage::new(Arc::clone(&events_db), Arc::clone(&db));

//     // Register not fully witnessed escrow, to save and reprocess events
//     let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
//     let escrow_db = Arc::new(EscrowDb::new(escrow_root.path())?);
//     let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
//         events_db.clone(),
//         db.clone(),
//         escrow_db,
//         Duration::from_secs(1),
//     ));
//     event_processor.register_observer(
//         partially_witnessed_escrow.clone(),
//         &[
//             JustNotification::PartiallyWitnessed,
//             JustNotification::ReceiptOutOfOrder,
//         ],
//     )?;

//     let id: IdentifierPrefix = "E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
//         .parse()
//         .unwrap();

//     let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBN_PYSns7oFNixSohVW4raBwMV6iYeh0PEZ_bR-38Xev0BDbyebqZQKwn7TqU92Vtw8n2wy5FptP42F1HEmCc9nQLzbXrXuA9SMl9nCZ-vi2bdaeT3aqInXGFAW70QPzM4kJ"#;
//     let parsed_rcp = parse(receipt0_0).unwrap().1;
//     let rcp_msg = Message::try_from(parsed_rcp).unwrap();
//     event_processor.process(&rcp_msg.clone())?;

//     // check if receipt was escrowed
//     let mut esc = partially_witnessed_escrow
//         .escrowed_nontranferable_receipts
//         .get_all()
//         .unwrap();
//     assert_eq!(
//         rcp_msg,
//         Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
//     );
//     assert!(esc.next().is_none());

//     let state = event_storage.get_state(&id);
//     assert_eq!(state, None);

//     // Wait until receipt become stale
//     thread::sleep(Duration::from_secs(1));

//     // Check escrow. Old receipt should be removed because it is stale.
//     let mut esc = partially_witnessed_escrow
//         .escrowed_nontranferable_receipts
//         .get_all()
//         .unwrap();
//     assert!(esc.next().is_none());

//     // Process one more receipt
//     let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","i":"EJufgwH347N2kobmes1IQw_1pfMipEFFy0RwinZTtah9","s":"0"}-CABBHndk6cXPCnghFqKt_0SikY1P9z_nIUrHq_SeHgLQCui0BBqAOBXFKVivgf0jh2ySWX1VshnkUYK3ev_L--sPB_onF7w2WhiK2AB7mf4IIuaSQCLumsr2sV77S6U5VMx0CAD"#;
//     let parsed_rcp = parse(receipt0_1).unwrap().1;
//     let rcp_msg = Message::try_from(parsed_rcp).unwrap();
//     event_processor.process(&rcp_msg.clone())?;

//     let state = event_storage.get_state(&id);
//     assert_eq!(state, None);

//     let mut esc = partially_witnessed_escrow
//         .escrowed_nontranferable_receipts
//         .get_all()
//         .unwrap();

//     assert_eq!(
//         rcp_msg,
//         Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
//     );
//     assert!(esc.next().is_none());

//     Ok(())
// }
