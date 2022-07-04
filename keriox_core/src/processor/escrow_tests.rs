use std::{
    convert::TryFrom,
    fs,
    sync::Arc,
    thread::{self, sleep},
    time::Duration,
};

use crate::{
    database::sled::SledEventDatabase,
    error::Error,
    event_message::signed_event_message::{Message, Notice, SignedEventMessage},
    event_parsing::message::{signed_event_stream, signed_message},
    prefix::IdentifierPrefix,
    processor::{basic_processor::BasicProcessor, event_storage::EventStorage, Processor},
};

#[test]
pub fn test_not_fully_witnessed() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = BasicProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));

    // check if receipt was escrowed
    let id: IdentifierPrefix = "E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
        .parse()
        .unwrap();

    // process icp event without processing receipts.
    let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0","kt":"2","k":["DtD9PUcL_NlTlvc2xiEJBRfRz0bDJlbtTynOQpNwVKh0","Dxb9OSQWxq59UsjRthaNPtTzNn8VXs8SJEXdbxFUZ-lA","DkQFb_911LXVQaFj-Ch9rj89QTpIZT3AcV-TjcBhbXOw"],"nt":"2","n":["EmigdEgCEjPPykB-u4_oW6xENmrnr1M0dNlkIUsx3dEI","EwnTsM2S1AKDnSjrnQF2OWRoPkcpH7aY1-3TtEJwnBMs","Eywk7noH2HheSFbjI-sids93CyzP4LUyJSOUBe7OAQbo"],"bt":"2","b":["B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I","BljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts"],"c":[],"a":[]}-AADAAhZMZp-TpUuGjfO-_s3gSh_aDpuK38b7aVh54W0LzgrOvA5Q3eULEch0hW8Ct6jHfLXSNCrsNSynT3D2UvymdCQABiDU4uO1sZcKh7_qlkVylf_jZDOAWlcJFY_ImBOIcfEZbNthQefZOL6EDzuxdUMEScKTnO_n1q3Ms8rufcz8lDwACQuxdJRTtPypGECC3nHdVkJeQojfRvkRZU7n15111NFbLAY2GpMAOnvptzIVUiv9ONOSCXBCWNFC4kNQmtDWOBg"#;
    let parsed_icp = signed_message(icp_raw).unwrap().1;
    let icp_msg = Message::try_from(parsed_icp).unwrap();
    event_processor.process(&icp_msg.clone())?;

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    // check if icp is in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert_eq!(
        icp_msg,
        Message::Notice(Notice::Event(esc.next().unwrap().signed_event_message))
    );
    assert!(esc.next().is_none());

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BlnRQL6bqNGJZNNGGwA4xZhBwtzY1SgAMdIFky-sUiq6bU-DGbp1OHSXQzKGQWlhohRxfcjtDjql8s9B_n5DdDw"#;
    let parsed_rcp = signed_message(receipt0_0).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // // check if icp still in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert_eq!(
        icp_msg,
        Message::Notice(Notice::Event(esc.next().unwrap().signed_event_message))
    );
    assert!(esc.next().is_none());

    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();
    assert_eq!(
        rcp_msg,
        Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
    );
    assert!(esc.next().is_none());

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I0BC69-inoBzibkf_HOUfn31sP3FOCukY0VqqOnnm6pxPWeBR2N7AhdN146OsHVuWfrzzuDSuJl3GpIPYCIynuEDA"#;
    let parsed_rcp = signed_message(receipt0_1).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if icp still in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert!(esc.next().is_none());

    // check if receipt was escrowed
    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();
    assert!(esc.next().is_none());

    // check if receipt was escrowed
    let esc = db.get_receipts_nt(&id).unwrap();
    assert_eq!(esc.count(), 2);

    let state = event_storage.get_state(&id)?.unwrap();
    assert_eq!(state.sn, 0);

    let receipt0_2 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts0BoXmoK-pNlcmdAzgWadjnhhfr2eAKiNxCqoWvx05tQyeZZazJx9rW-wQ_jjLieC7OsKDs6c0rEDHFaVgI9SfkDg"#;
    let parsed_rcp = signed_message(receipt0_2).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if receipt was escrowed
    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();
    assert!(esc.next().is_none());

    let esc = db.get_receipts_nt(&id).unwrap();
    assert_eq!(esc.count(), 3);

    Ok(())
}

#[cfg(feature = "query")]
#[test]
pub fn test_reply_escrow() -> Result<(), Error> {
    use tempfile::Builder;

    use crate::{
        event_message::signed_event_message::Op,
        event_parsing::message::signed_event_stream,
        processor::{escrow::ReplyEscrow, Processor},
    };

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let mut event_processor = BasicProcessor::new(Arc::clone(&db));
    event_processor.register_observer(Arc::new(ReplyEscrow::new(db.clone())))?;

    let identifier: IdentifierPrefix = "E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0".parse()?;
    let kel = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"0","kt":"1","k":["DqI2cOZ06RwGNwCovYUWExmdKU983IasmUKMmZflvWdQ"],"nt":"1","n":["EOmBSdblll8qB4324PEmETrFN-DhElyZ0BcBH1q1qukw"],"bt":"0","b":[],"c":[],"a":[]}-AABAAotHSmS5LuCg2LXwlandbAs3MFR0yTC5BbE2iSW_35U2qA0hP9gp66G--mHhiFmfHEIbBKrs3tjcc8ySvYcpiBg{"v":"KERI10JSON000160_","t":"rot","d":"EFE9Je3kPu4PrLZg7_ixdD_ISn7FopBVfnSj2dvRgi6Q","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"1","p":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","kt":"1","k":["Dyb48eeVVXD7JAarHFAUffKcgYGvCQ4KWX00myzNLgzU"],"nt":"1","n":["EQiKHrrsf2ogDeMCsAckDhB2qVNFejbAd1BOgetxGUAM"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAQOn_2iHAT0Z_WH_C2mrlMA5F2x0EhnUlvzvjQUk-CMSR5YDV2v6YtABlsvvpcLES7m6D3hbsTxZTlKiQDQVSCA{"v":"KERI10JSON000160_","t":"rot","d":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"2","p":"EFE9Je3kPu4PrLZg7_ixdD_ISn7FopBVfnSj2dvRgi6Q","kt":"1","k":["DyN13SKiF1FsVoVR5C4r_15JJLUBxBXBmkleD5AYWplc"],"nt":"1","n":["ETbCFP46-4PxwjUdYbexS5xk_wcH7R0m1wyYnEpOLv70"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAwBxL1dmS_lnOBXW8SAI5kFenwrjd40KJ3cQfY9OCa1KtmtYN7PC19zSHdjxUWd_-8xphzRIEjgS1TlfBsy-Bw{"v":"KERI10JSON000160_","t":"rot","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAKxPycYU7BbajlGN3sFjOBalZLwV38eXjcgvzNSetT7WARTgxsUpMStd242T09egL1wS_--d0xtOo1wLDXIbRAQ"#;
    let parsed = signed_event_stream(kel.as_bytes()).unwrap().1;
    let kel_events = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let rest_of_kel = r#"{"v":"KERI10JSON000160_","t":"rot","d":"EJOferfZnYAGC97N8aQ4iA8h-PWQqEmn20_Xw8GuzEGI","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"4","p":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","kt":"1","k":["DcJ_93nB6lFRiuTCKLsP0P-LH2bxgnW7pzsp_i8KEHb4"],"nt":"1","n":["EWUzw9KfQume7PZuHxQ_i0YyBxmBYEfTkk5ePhryIBgk"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA0kU4YWNlKLPEyR_0ei9F4bSa_WNudC5EYd7tJEEqOsYiRpAu_cQjGrA_8kbn1aouva-rciB3_pXQJRgUfgSLDw{"v":"KERI10JSON000160_","t":"rot","d":"E4cbKMhJUbGJ_reYb2G7P5MGx81jsPJK4zHQFsBMt3Qg","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"5","p":"EJOferfZnYAGC97N8aQ4iA8h-PWQqEmn20_Xw8GuzEGI","kt":"1","k":["Dw4Woc1Nto6vNe_oezp3Tw13-YujvCIf7zzy8Ua0VaZU"],"nt":"1","n":["Edpe-GQqyPFNDplFcDSTH5MvKGrh3jobt644h9xX-1TY"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAvWr9JXCUBFElE-FyRWclfsj9AfOG8xRwx9oteKWd7OE7A9acsntkw5Rym5qKEesaDgR2jfTQ39dMbSgDu19tDA{"v":"KERI10JSON000160_","t":"rot","d":"ESr4nKerE-jD2Fus-SZ89vqw28NspZtvfZbJCoh-xTLo","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"6","p":"E4cbKMhJUbGJ_reYb2G7P5MGx81jsPJK4zHQFsBMt3Qg","kt":"1","k":["DjGxCjRAVaFiVffhQcPDf04bicivm2TL1LknCL3ujv50"],"nt":"1","n":["ExVrRvLl-lgl5vhALTzjQR6QBRVj5qK_nYLsXdrQcJxI"],"bt":"0","br":[],"ba":[],"a":[]}-AABAA_-nm9MzcLmED4MRYn3Q37zuuCuOCp5E33ol5n0HbIYSRiH169BMCSGZ4lOShjntuvA8YX6CPVj8savnAoE7RAw{"v":"KERI10JSON000160_","t":"rot","d":"EdQ_x7-gzmnNc6Ey8gTUXWG_pmBR_krsJvHzmcAyNspA","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"7","p":"ESr4nKerE-jD2Fus-SZ89vqw28NspZtvfZbJCoh-xTLo","kt":"1","k":["DwTncFFLkqdfOx9ipPwjYMJ-Xqcw6uVgE38WbfAiH0zQ"],"nt":"1","n":["EsOYyyK159rRQ9thyYIFW_eatb5caqYfm7KQb_gHmr6I"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAXz5lIHtDvKBiLXQFnHMXhI3LPF1gK2FzepUaJriwnvRYLoZGZdNj9RhfHO5OF1SEngdd9bztgurOo-6J9LmUAg{"v":"KERI10JSON000160_","t":"rot","d":"EHjIAl52sHElD94gCtKAdBqMUvDy04r0u35zMa4HJpFU","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"8","p":"EdQ_x7-gzmnNc6Ey8gTUXWG_pmBR_krsJvHzmcAyNspA","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"nt":"1","n":["EbB6xA74q3sWQFwFbfhIpfW_UFdmvdTv-Z1iKQ9ZQXHI"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4gejkpgDKwOx7HP2SgsFMg-47RFR5UoMiuYtoY4Ff5NDxEGEv8Nq2hVYOzi3kGclBgglQeVmfZt2QnJzmBUCg"#;
    let parsed = signed_event_stream(rest_of_kel.as_bytes()).unwrap().1;
    let rest_of_kel = parsed.into_iter().map(|ev| Message::try_from(ev).unwrap());

    let old_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EYFMuK9IQmHvq9KaJ1r67_MMCq5GnQEgLyN9YPamR3r0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"3","p":"EF7f4gNFCbJz6ZHLacIi_bbIq7kaWAFOzX7ncU_vs5Qg","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","f":"3","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DrcAz_gmDTuWIHn_mOQDeSK_aJIRiw5IMzPD7igzEDb0"],"nt":"1","n":["EK7ZUmFebD2st48Yvtzc9LajV3Yg2mkeeDzVRL-7uKrU"],"bt":"0","b":[],"c":[],"ee":{"s":"3","d":"EOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAAAwEOPSPvHHVmU9IIdHa5ksisoVrOnmHRps_tx3OsZSQQ30-AABAAYsqumzPM0bIo04gJ4Ln0zAOsGVnjHZrFjjjS49hGx_nQKbXuD1D4J_jNoEa4TPtPDnQ8d0YcJ4TIRJb-XouJBg"#;
    let parsed = signed_message(old_rpy.as_bytes()).unwrap().1;
    let deserialized_old_rpy = Message::try_from(parsed).unwrap();

    let new_rpy = r#"{"v":"KERI10JSON00029d_","t":"rpy","d":"EIgqNqtNe06ngzIzB6lp8nsyYYG3xb41UZGRMjZ_TOD0","dt":"2021-01-01T00:00:00.000000+00:00","r":"/ksn/E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","a":{"v":"KERI10JSON0001e2_","i":"E7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ0","s":"8","p":"EdQ_x7-gzmnNc6Ey8gTUXWG_pmBR_krsJvHzmcAyNspA","d":"EHjIAl52sHElD94gCtKAdBqMUvDy04r0u35zMa4HJpFU","f":"8","dt":"2021-01-01T00:00:00.000000+00:00","et":"rot","kt":"1","k":["DOedRyfIQe4Z-GNSlbgA8txIKyx4Li2tJ1S0Yhy7l2T8"],"nt":"1","n":["EbB6xA74q3sWQFwFbfhIpfW_UFdmvdTv-Z1iKQ9ZQXHI"],"bt":"0","b":[],"c":[],"ee":{"s":"8","d":"EHjIAl52sHElD94gCtKAdBqMUvDy04r0u35zMa4HJpFU","br":[],"ba":[]},"di":""}}-VA0-FABE7YbTIkWWyNwOxZQTTnrs6qn8jFbu2A8zftQ33JYQFQ00AAAAAAAAAAAAAAAAAAAAACAEHjIAl52sHElD94gCtKAdBqMUvDy04r0u35zMa4HJpFU-AABAAqI5o_7wWWIl-xL2OhFmzaEXjeitckyJkWHaybt_jcU1q2B-haclpR7qXqKVqTUID7NQrHrzGx5yonOycKT6jDg"#;
    let parsed = signed_message(new_rpy.as_bytes()).unwrap().1;
    let deserialized_new_rpy = Message::try_from(parsed).unwrap();

    // Try to process out of order reply
    event_processor.process(&deserialized_old_rpy.clone())?;

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
fn test_out_of_order() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"0","kt":"1","k":["DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA"],"nt":"1","n":["EIGzh8BtHEKJ2b8tCpT6ViPg_BG1C24J6H1-x3kZgujM"],"bt":"0","b":[],"c":[],"a":[]}-AABAANivtUYYh6eDXCV_B-Bn0hoXhUb1QIKj12v4qEvyfP5Ivv9ptqYECIp1Jh8AGWeQ5jsvvF0Qg4oYr9iRXwTOgDA{"v":"KERI10JSON000160_","t":"rot","d":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"1","p":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","kt":"1","k":["Dv3nISHlvrOn7UjG2YIgBsVsDBnbYBtkmntEMhU3h5Y0"],"nt":"1","n":["E8KLV_FkyNHuhQJWvMWPY1iq69quTjQMqS2h0GJOM8so"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAPagtTdU6s0pzR-rzc2kaw3nl7sVdqALpa73iH5jfphOo-yBP-678rd3CjNUMmaf5l82qI_DUeArUz14y_BGVCA{"v":"KERI10JSON0000cb_","t":"ixn","d":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"2","p":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","a":[]}-AABAAxMLK-Y1TJ4SZNlEZ-wbGHnmzj_xGLeACwYxdxuFXK8jELRKv1sOYxh-cONWzX3MBr8Tw-CUQcXjdX72urYPJAg{"v":"KERI10JSON000160_","t":"rot","d":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"3","p":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","kt":"1","k":["DSrbxtHTjT7h2TKzahHmoPLMUwo_EUM-UAZLhamDbwDo"],"nt":"1","n":["EcoDGJfkoo_db4Q6_eysxz3U-pHE_2PlC7haQx4bYvgA"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAaWu4AEHtTJlZmkKCxsWQzYVgDBPBK2Q-QltsqzNXMexvQZSZ6nbRLXKOl3L8e03ibGCdjgfE68TSaej35gv4CA{"v":"KERI10JSON000160_","t":"rot","d":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"4","p":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","kt":"1","k":["DgFazXLwbkgvWpG1C7CkbFIJ73xYXTYsz5ls7Reay9_Q"],"nt":"1","n":["EAsZ5c_oWSgcUnrSOnJGGK_N-rJOG8ZPy8Nf0XYg9Vxc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4-A5mqR3Qe-aQ7kpz2TYIn95Iq3tEQIPhAJFfLDyEpDEwa62sk9mxTsbr71bKCNCZW0QFIcQlNqENBeCx1GBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"EIxaIr-vj-evDQTV9jYu1zGQXm0x4W4sCgnXij0H_mRM","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"5","p":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAVWwMR7338dUwKV1hDxHGVyMO91hDBaRDiI2EoxC3kkOlWWRUD_YWwc3dlxDPD8_nPvEkRL7ravw-Cfn9K_BpBQ"#;
    let mut kell = signed_event_stream(kel)
        .unwrap()
        .1
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let ev3 = kell.next().unwrap();
    let ev4 = kell.next().unwrap();
    let ev5 = kell.next().unwrap();

    use tempfile::Builder;

    let (processor, storage) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        (
            BasicProcessor::new(witness_db.clone()),
            EventStorage::new(witness_db.clone()),
        )
    };
    let id: IdentifierPrefix = "DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    processor.process(&ev4.clone())?;
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    processor.process(&ev3.clone())?;
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev4.clone())
    );
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev3.clone())
    );
    assert!(escrowed.next().is_none());

    processor.process(&ev5.clone())?;
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev4.clone())
    );
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev3.clone())
    );
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev5.clone())
    );
    assert!(escrowed.next().is_none());

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);
    // check out of order table
    assert_eq!(storage.db.get_out_of_order_events(&id).unwrap().count(), 3);

    processor.process(&ev2)?;

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 4);
    // Check if out of order is empty
    assert!(storage
        .db
        .get_out_of_order_events(&id)
        .unwrap()
        .next()
        .is_none());

    Ok(())
}

#[test]
fn test_escrow_missing_signatures() -> Result<(), Error> {
    use crate::event_parsing::{message::event_message, EventType};
    let kel = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"0","kt":"1","k":["DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA"],"nt":"1","n":["EIGzh8BtHEKJ2b8tCpT6ViPg_BG1C24J6H1-x3kZgujM"],"bt":"0","b":[],"c":[],"a":[]}-AABAANivtUYYh6eDXCV_B-Bn0hoXhUb1QIKj12v4qEvyfP5Ivv9ptqYECIp1Jh8AGWeQ5jsvvF0Qg4oYr9iRXwTOgDA{"v":"KERI10JSON000160_","t":"rot","d":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"1","p":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","kt":"1","k":["Dv3nISHlvrOn7UjG2YIgBsVsDBnbYBtkmntEMhU3h5Y0"],"nt":"1","n":["E8KLV_FkyNHuhQJWvMWPY1iq69quTjQMqS2h0GJOM8so"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAPagtTdU6s0pzR-rzc2kaw3nl7sVdqALpa73iH5jfphOo-yBP-678rd3CjNUMmaf5l82qI_DUeArUz14y_BGVCA"#; //{"v":"KERI10JSON0000cb_","t":"ixn","d":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"2","p":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","a":[]}"#;//-AABAAxMLK-Y1TJ4SZNlEZ-wbGHnmzj_xGLeACwYxdxuFXK8jELRKv1sOYxh-cONWzX3MBr8Tw-CUQcXjdX72urYPJAg"#;//{"v":"KERI10JSON000160_","t":"rot","d":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"3","p":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","kt":"1","k":["DSrbxtHTjT7h2TKzahHmoPLMUwo_EUM-UAZLhamDbwDo"],"nt":"1","n":["EcoDGJfkoo_db4Q6_eysxz3U-pHE_2PlC7haQx4bYvgA"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAaWu4AEHtTJlZmkKCxsWQzYVgDBPBK2Q-QltsqzNXMexvQZSZ6nbRLXKOl3L8e03ibGCdjgfE68TSaej35gv4CA{"v":"KERI10JSON000160_","t":"rot","d":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"4","p":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","kt":"1","k":["DgFazXLwbkgvWpG1C7CkbFIJ73xYXTYsz5ls7Reay9_Q"],"nt":"1","n":["EAsZ5c_oWSgcUnrSOnJGGK_N-rJOG8ZPy8Nf0XYg9Vxc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4-A5mqR3Qe-aQ7kpz2TYIn95Iq3tEQIPhAJFfLDyEpDEwa62sk9mxTsbr71bKCNCZW0QFIcQlNqENBeCx1GBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"EIxaIr-vj-evDQTV9jYu1zGQXm0x4W4sCgnXij0H_mRM","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"5","p":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAVWwMR7338dUwKV1hDxHGVyMO91hDBaRDiI2EoxC3kkOlWWRUD_YWwc3dlxDPD8_nPvEkRL7ravw-Cfn9K_BpBQ"#;
    let event_without_signature_str = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"2","p":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","a":[]}"#; //-AABAAxMLK-Y1TJ4SZNlEZ-wbGHnmzj_xGLeACwYxdxuFXK8jELRKv1sOYxh-cONWzX3MBr8Tw-CUQcXjdX72urYPJAg"#;//{"v":"KERI10JSON000160_","t":"rot","d":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"3","p":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","kt":"1","k":["DSrbxtHTjT7h2TKzahHmoPLMUwo_EUM-UAZLhamDbwDo"],"nt":"1","n":["EcoDGJfkoo_db4Q6_eysxz3U-pHE_2PlC7haQx4bYvgA"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAaWu4AEHtTJlZmkKCxsWQzYVgDBPBK2Q-QltsqzNXMexvQZSZ6nbRLXKOl3L8e03ibGCdjgfE68TSaej35gv4CA{"v":"KERI10JSON000160_","t":"rot","d":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"4","p":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","kt":"1","k":["DgFazXLwbkgvWpG1C7CkbFIJ73xYXTYsz5ls7Reay9_Q"],"nt":"1","n":["EAsZ5c_oWSgcUnrSOnJGGK_N-rJOG8ZPy8Nf0XYg9Vxc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4-A5mqR3Qe-aQ7kpz2TYIn95Iq3tEQIPhAJFfLDyEpDEwa62sk9mxTsbr71bKCNCZW0QFIcQlNqENBeCx1GBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"EIxaIr-vj-evDQTV9jYu1zGQXm0x4W4sCgnXij0H_mRM","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"5","p":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAVWwMR7338dUwKV1hDxHGVyMO91hDBaRDiI2EoxC3kkOlWWRUD_YWwc3dlxDPD8_nPvEkRL7ravw-Cfn9K_BpBQ"#;
    let mut kell = signed_event_stream(kel)
        .unwrap()
        .1
        .into_iter()
        .map(|e| Message::try_from(e).unwrap());
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let (event_without_signatures, event) =
        match event_message(event_without_signature_str).unwrap().1 {
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

    let (processor, storage) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        (
            BasicProcessor::new(witness_db.clone()),
            EventStorage::new(witness_db.clone()),
        )
    };
    let id: IdentifierPrefix = "DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    // Process out of order event without signatures
    processor.process(&event_without_signatures)?;

    assert!(storage.db.get_out_of_order_events(&id).is_none(),);

    // try to process unsigned event, but in order
    processor.process(&ev2)?;
    processor.process(&event_without_signatures)?;

    // check partially signed escrow
    assert!(storage.db.get_partially_signed_events(event).is_none());

    Ok(())
}

#[test]
fn test_partially_sign_escrow() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        let processor = BasicProcessor::new(witness_db.clone());

        (processor, EventStorage::new(witness_db.clone()))
    };

    let parse_messagee = |raw_event| {
        let parsed = signed_message(raw_event).unwrap().1;
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

    let mut escrowed = storage.db.get_partially_signed_events(icp_event).unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(icp_first_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap(), None);

    // check escrow
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    processor.process(&icp_second_sig)?;

    // Now event is fully signed, check if escrow is emty
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert!(storage.get_state(&id).unwrap().is_some());

    let ixn = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"1","p":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","a":[]}-AABABHu-KLKX52wTZCwE4u_MEWrvPQ8kC_XSgzQ7Mqmrhv4imCCTaoiCCH2JbebIvfOHXlmwVwntz9B89qbf7SLT8Bg"#;
    let ixn_first_sig = parse_messagee(ixn);

    let ixn2 = br#"{"v":"KERI10JSON0000cb_","t":"ixn","d":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"1","p":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","a":[]}-AABAAye1jlp6iz6h5raVAavZEEahPQ7mUVHxegfjgZCjaWA-UcSQi5ic59-PKQ0tlEHlNHaeKIPts0lvONpW71dgOAg"#;
    let ixn_second_sig = parse_messagee(ixn2);

    processor.process(&ixn_first_sig)?;

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    // check escrow
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        1
    );

    // Proces the same event with another signature
    processor.process(&ixn_second_sig)?;

    // Now event is fully signed, check if escrow is empty
    assert_eq!(
        storage
            .db
            .get_all_partially_signed_events()
            .unwrap()
            .count(),
        0
    );
    // check if event was accepted
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 1);

    let rot = parse_messagee(br#"{"v":"KERI10JSON0002aa_","t":"rot","d":"Ep2O4Nr3NDhQjPe5IfEQmfW1MExEIj1nUN55ZxboaaQI","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"2","p":"ErcMMcfO4fdplItWB_42GwyY21u0pJkQEVDvMmrLVgFc","kt":["1/2","1/2","1/2"],"k":["DeonYM2bKnAwp6VZcuCXdX72kNFw56czlZ_Tc7XHHVGI","DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc5QF8x50tRoU","DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA"],"nt":[["1/2","1/2","1/2"],["1/1","1/1"]],"n":["ERDESHlo0cEajbxFhWuS8fTBIkYdSlKs3qXm7hNKZV94","E6O7UqeJdpNR99CAFGLMRxvzVWRjrITDW2pLvSQpH_do","EcsXdhvTdA_Si7zimi9ihxlos3Fg_YDKb9J-Qj8XeH50","E8voIy-QfZ3N20SdeOobrTgBgFrmd6BDg3vGuMkkCyGc","EImFU5Xrt6Cv7n8wug9xkJL8_5WwhaI5sXfLZT9Ql9_o"],"bt":"0","br":[],"ba":[],"a":[]}-AADAA1nZhgIcktY781gpGGAb757ylwmaAYi6zsQkEk5Y9wNU-zaEWSXY4ycG3w_Wxt8Xr2zzicMSh6maehmKFx8sMDgABRKx6GPksk0FbaP7w_t6rtoOK-JsBqq6D_-p9t9t79VxEHy8fGCbRUJVxb3TjBckgnqwyjmLVd3RIK3idOYC6DgACszQvR87NLPEcujHLnFgBOGgudSEVXWdnuHfxCBLvSCm3JrELZkpOa5bzAy84PSGeu9MFj0HeuEYj0y4MF9PYCw"#);

    processor.process(&rot)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 2);
    Ok(())
}

#[test]
fn test_out_of_order_cleanup() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON00012b_","t":"icp","d":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"0","kt":"1","k":["DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA"],"nt":"1","n":["EIGzh8BtHEKJ2b8tCpT6ViPg_BG1C24J6H1-x3kZgujM"],"bt":"0","b":[],"c":[],"a":[]}-AABAANivtUYYh6eDXCV_B-Bn0hoXhUb1QIKj12v4qEvyfP5Ivv9ptqYECIp1Jh8AGWeQ5jsvvF0Qg4oYr9iRXwTOgDA{"v":"KERI10JSON000160_","t":"rot","d":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"1","p":"EWzkqMDJfu5F78Xgw-WWhBChv7zNHJu6oa9UuWR3YARQ","kt":"1","k":["Dv3nISHlvrOn7UjG2YIgBsVsDBnbYBtkmntEMhU3h5Y0"],"nt":"1","n":["E8KLV_FkyNHuhQJWvMWPY1iq69quTjQMqS2h0GJOM8so"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAPagtTdU6s0pzR-rzc2kaw3nl7sVdqALpa73iH5jfphOo-yBP-678rd3CjNUMmaf5l82qI_DUeArUz14y_BGVCA{"v":"KERI10JSON0000cb_","t":"ixn","d":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"2","p":"EhgEE5xyPyDvZaa61YpXv9olrlgTuYfRAd3eSAxs38tE","a":[]}-AABAAxMLK-Y1TJ4SZNlEZ-wbGHnmzj_xGLeACwYxdxuFXK8jELRKv1sOYxh-cONWzX3MBr8Tw-CUQcXjdX72urYPJAg{"v":"KERI10JSON000160_","t":"rot","d":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"3","p":"EWCY9lCq1CmlO-bxxz2xHr3ZRWmpxPaPg9MYOsJe84-4","kt":"1","k":["DSrbxtHTjT7h2TKzahHmoPLMUwo_EUM-UAZLhamDbwDo"],"nt":"1","n":["EcoDGJfkoo_db4Q6_eysxz3U-pHE_2PlC7haQx4bYvgA"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAaWu4AEHtTJlZmkKCxsWQzYVgDBPBK2Q-QltsqzNXMexvQZSZ6nbRLXKOl3L8e03ibGCdjgfE68TSaej35gv4CA{"v":"KERI10JSON000160_","t":"rot","d":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"4","p":"Epkwu4R--j3r_FR2JoDRku4bHk8F824FJAs1JtJr0niY","kt":"1","k":["DgFazXLwbkgvWpG1C7CkbFIJ73xYXTYsz5ls7Reay9_Q"],"nt":"1","n":["EAsZ5c_oWSgcUnrSOnJGGK_N-rJOG8ZPy8Nf0XYg9Vxc"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAC4-A5mqR3Qe-aQ7kpz2TYIn95Iq3tEQIPhAJFfLDyEpDEwa62sk9mxTsbr71bKCNCZW0QFIcQlNqENBeCx1GBA{"v":"KERI10JSON0000ff_","t":"ixn","d":"EIxaIr-vj-evDQTV9jYu1zGQXm0x4W4sCgnXij0H_mRM","i":"DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA","s":"5","p":"EJRFvIIsjIkxcS82a3z5iDnfIG7pFS_sfE42KHdEMas8","a":[,{"d""E7JCRX6JqsBKomojsyLR-TddsSt_Wq9H8EOMhsPyhjR0"}]}-AABAAVWwMR7338dUwKV1hDxHGVyMO91hDBaRDiI2EoxC3kkOlWWRUD_YWwc3dlxDPD8_nPvEkRL7ravw-Cfn9K_BpBQ"#;
    let mut kell = signed_event_stream(kel)
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

    let (processor, storage) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        (
            BasicProcessor::new(witness_db.clone()),
            EventStorage::new(witness_db.clone()),
        )
    };
    let id: IdentifierPrefix = "DW-CM1BxXJO2fgMGqgvJBbi0UfxGFI0mpxDBVBNxXKoA".parse()?;

    processor.process(&ev1)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    // Process out of order event and check escrow.
    processor.process(&ev4.clone())?;
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    // Process one more out of order event.
    processor.process(&ev3.clone())?;

    // Wait until escrowed events become stale.
    thread::sleep(Duration::from_secs(10));

    // Process inorder missing event.
    processor.process(&ev2.clone())?;

    // Escrow should be empty
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert!(escrowed.next().is_none());

    // Stale events shouldn't be save in the kel.
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 1);

    // Process out of order events once again and check escrow.
    processor.process(&ev4.clone())?;
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();

    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(ev4.clone())
    );
    assert!(escrowed.next().is_none());

    // Process inorder missing event.
    processor.process(&ev3.clone())?;

    // Escrow should be empty
    let mut escrowed = storage.db.get_out_of_order_events(&id).unwrap();
    assert!(escrowed.next().is_none());

    // Events should be accepted, they're not stale..
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 3);

    Ok(())
}

#[test]
fn test_partially_sign_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        let witness_db = Arc::new(SledEventDatabase::new(path).unwrap());
        std::fs::create_dir_all(path).unwrap();
        let processor = BasicProcessor::new(witness_db.clone());

        (processor, EventStorage::new(witness_db.clone()))
    };

    let parse_messagee = |raw_event| {
        let parsed = signed_message(raw_event).unwrap().1;
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

    let mut escrowed = storage
        .db
        .get_partially_signed_events(icp_event.clone())
        .unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(icp_first_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap(), None);

    // Wait until escrowed events become stale.
    thread::sleep(Duration::from_secs(10));

    // Proces the same event with another signature
    processor.process(&icp_second_sig)?;

    // check escrow
    let mut escrowed = storage
        .db
        .get_partially_signed_events(icp_event.clone())
        .unwrap();
    assert_eq!(
        escrowed
            .next()
            .map(|e| Message::Notice(Notice::Event(e.signed_event_message))),
        Some(icp_second_sig.clone())
    );
    assert!(escrowed.next().is_none());

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id).unwrap(), None);

    // Proces the same event with another signature
    processor.process(&icp_first_sig)?;

    Ok(())
}

#[test]
pub fn test_partially_witnessed_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = BasicProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));

    // check if receipt was escrowed
    let id: IdentifierPrefix = "E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
        .parse()
        .unwrap();

    // process icp event without processing receipts.
    let icp_raw = br#"{"v":"KERI10JSON000273_","t":"icp","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0","kt":"2","k":["DtD9PUcL_NlTlvc2xiEJBRfRz0bDJlbtTynOQpNwVKh0","Dxb9OSQWxq59UsjRthaNPtTzNn8VXs8SJEXdbxFUZ-lA","DkQFb_911LXVQaFj-Ch9rj89QTpIZT3AcV-TjcBhbXOw"],"nt":"2","n":["EmigdEgCEjPPykB-u4_oW6xENmrnr1M0dNlkIUsx3dEI","EwnTsM2S1AKDnSjrnQF2OWRoPkcpH7aY1-3TtEJwnBMs","Eywk7noH2HheSFbjI-sids93CyzP4LUyJSOUBe7OAQbo"],"bt":"2","b":["B389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd68","Bed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I","BljDbmdNfb63KOpGV4mmPKwyyp3OzDsRzpNrdL1BRQts"],"c":[],"a":[]}-AADAAhZMZp-TpUuGjfO-_s3gSh_aDpuK38b7aVh54W0LzgrOvA5Q3eULEch0hW8Ct6jHfLXSNCrsNSynT3D2UvymdCQABiDU4uO1sZcKh7_qlkVylf_jZDOAWlcJFY_ImBOIcfEZbNthQefZOL6EDzuxdUMEScKTnO_n1q3Ms8rufcz8lDwACQuxdJRTtPypGECC3nHdVkJeQojfRvkRZU7n15111NFbLAY2GpMAOnvptzIVUiv9ONOSCXBCWNFC4kNQmtDWOBg"#;
    let parsed_icp = signed_message(icp_raw).unwrap().1;
    let icp_msg = Message::try_from(parsed_icp).unwrap();
    event_processor.process(&icp_msg.clone())?;

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BlnRQL6bqNGJZNNGGwA4xZhBwtzY1SgAMdIFky-sUiq6bU-DGbp1OHSXQzKGQWlhohRxfcjtDjql8s9B_n5DdDw"#;
    let parsed_rcp = signed_message(receipt0_0).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if icp is in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert_eq!(
        icp_msg,
        Message::Notice(Notice::Event(esc.next().unwrap().signed_event_message))
    );
    assert!(esc.next().is_none());

    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();
    assert_eq!(
        rcp_msg,
        Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
    );
    assert!(esc.next().is_none());

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    // Wait until escrowed events become stale.
    sleep(Duration::from_secs(10));

    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I0BC69-inoBzibkf_HOUfn31sP3FOCukY0VqqOnnm6pxPWeBR2N7AhdN146OsHVuWfrzzuDSuJl3GpIPYCIynuEDA"#;
    let parsed_rcp = signed_message(receipt0_1).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if icp still in escrow
    let mut esc = db.get_all_partially_witnessed().unwrap();
    assert!(esc.next().is_none());

    // check if event was accepted into kel
    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    Ok(())
}

#[test]
pub fn test_nt_receipt_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // Create test db and event processor.
    // events taken from keripy/tests/core/test_witness.py:def test_indexed_witness_replay():
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let event_processor = BasicProcessor::new(Arc::clone(&db));
    let event_storage = EventStorage::new(Arc::clone(&db));

    let id: IdentifierPrefix = "E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U"
        .parse()
        .unwrap();

    let receipt0_0 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABB389hKezugU2LFKiFVbitoHAxXqJh6HQ8Rn9tH7fxd680BlnRQL6bqNGJZNNGGwA4xZhBwtzY1SgAMdIFky-sUiq6bU-DGbp1OHSXQzKGQWlhohRxfcjtDjql8s9B_n5DdDw"#;
    let parsed_rcp = signed_message(receipt0_0).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    // check if receipt was escrowed
    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();
    assert_eq!(
        rcp_msg,
        Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
    );
    assert!(esc.next().is_none());

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    // Wait until receipt become stale
    thread::sleep(Duration::from_secs(10));

    // Process one more receipt
    let receipt0_1 = br#"{"v":"KERI10JSON000091_","t":"rct","d":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","i":"E1EyzzujHLiQbj9kcJ9wI2lVjOkiNbNn7t4Y2MhRjn_U","s":"0"}-CABBed2Tpxc8KeCEWoq3_RKKRjU_3P-chSser9J4eAtAK6I0BC69-inoBzibkf_HOUfn31sP3FOCukY0VqqOnnm6pxPWeBR2N7AhdN146OsHVuWfrzzuDSuJl3GpIPYCIynuEDA"#;
    let parsed_rcp = signed_message(receipt0_1).unwrap().1;
    let rcp_msg = Message::try_from(parsed_rcp).unwrap();
    event_processor.process(&rcp_msg.clone())?;

    let state = event_storage.get_state(&id)?;
    assert_eq!(state, None);

    // Check escrow. Old receipt should be removed because it is stale.
    let mut esc = db.get_escrow_nt_receipts(&id).unwrap();

    assert_eq!(
        rcp_msg,
        Message::Notice(Notice::NontransferableRct(esc.next().unwrap().into()))
    );
    assert!(esc.next().is_none());

    Ok(())
}
