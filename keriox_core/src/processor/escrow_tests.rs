use std::{
    convert::TryFrom,
    fs,
    sync::Arc,
    thread::{self},
    time::Duration,
};

use cesrox::{parse, parse_many};
use tempfile::NamedTempFile;

use crate::{
    database::{redb::RedbDatabase, EscrowDatabase},
    error::Error,
    event_message::signed_event_message::{Message, Notice},
    prefix::IdentifierPrefix,
    processor::{
        basic_processor::BasicProcessor,
        escrow::{
            maybe_out_of_order_escrow::MaybeOutOfOrderEscrow,
            partially_signed_escrow::PartiallySignedEscrow,
            partially_witnessed_escrow::PartiallyWitnessedEscrow,
        },
        event_storage::EventStorage,
        notification::JustNotification,
        Processor,
    },
};

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
        let events_db_path = NamedTempFile::new().unwrap();
        let redb = RedbDatabase::new(events_db_path.path()).unwrap();
        let events_db = Arc::new(redb);
        let processor = BasicProcessor::new(events_db.clone(), None);

        // Register out of order escrow, to save and reprocess out of order events
        let ooo_escrow = Arc::new(MaybeOutOfOrderEscrow::new(
            events_db.clone(),
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
        (processor, EventStorage::new(events_db.clone()), ooo_escrow)
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

#[ignore]
#[test]
fn test_partially_sign_escrow_cleanup() -> Result<(), Error> {
    use tempfile::Builder;

    // events from keripy/tests/core/test_escrow.py::test_partial_signed_escrow
    let (processor, storage, ps_escrow) = {
        let witness_root = Builder::new().prefix("test-db").tempdir().unwrap();
        let path = witness_root.path();
        std::fs::create_dir_all(path).unwrap();
        let events_db_path = NamedTempFile::new().unwrap();
        let events_db = Arc::new(RedbDatabase::new(events_db_path.path()).unwrap());
        let processor = BasicProcessor::new(events_db.clone(), None);

        // Register partially signed escrow, to save and reprocess partially signed events
        let ps_escrow = Arc::new(PartiallySignedEscrow::new(
            events_db.clone(),
            Duration::from_secs(1),
        ));
        processor.register_observer(ps_escrow.clone(), &[JustNotification::PartiallySigned])?;

        (processor, EventStorage::new(events_db), ps_escrow)
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

    let escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert_eq!(
        Message::Notice(Notice::Event(escrowed)),
        icp_first_sig.clone()
    );

    // check if event was accepted into kel
    assert_eq!(storage.get_state(&id), None);

    // Wait until escrowed events become stale.
    thread::sleep(Duration::from_secs(1));

    // Check if stale event was removed
    let escrowed = ps_escrow.get_partially_signed_for_event(icp_event.clone());
    assert!(escrowed.is_none());

    // Proces the same event with another signature
    processor.process(&icp_second_sig)?;

    // check escrow
    let escrowed = ps_escrow
        .get_partially_signed_for_event(icp_event.clone())
        .unwrap();
    assert_eq!(
        Message::Notice(Notice::Event(escrowed)),
        icp_second_sig.clone()
    );

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
    let events_db_path = NamedTempFile::new().unwrap();

    let redb = RedbDatabase::new(events_db_path.path()).unwrap();
    let log_db = redb.log_db.clone();
    let events_db = Arc::new(redb);
    let event_processor = BasicProcessor::new(events_db.clone(), None);
    let event_storage = EventStorage::new(Arc::clone(&events_db));
    // Register not fully witnessed escrow, to save and reprocess events
    let partially_witnessed_escrow = Arc::new(PartiallyWitnessedEscrow::new(
        events_db.clone(),
        log_db,
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
