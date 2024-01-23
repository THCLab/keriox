use std::sync::Arc;

use keri_core::{
    actor::{parse_notice_stream, process_notice},
    database::{escrow::EscrowDb, SledEventDatabase},
    error::Error,
    event_message::signed_event_message::Notice,
    prefix::IdentifierPrefix,
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig},
        event_storage::EventStorage,
    },
};
#[test]
fn test_out_of_order() -> Result<(), Error> {
    let kel = br#"{"v":"KERI10JSON000159_","t":"icp","d":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"0","kt":"1","k":["DODv7KGqEEhAP7-VYXzZvNi5wmgEB8w5y6HLUQL08PNh"],"nt":"1","n":["ECo41Mn5wku-tQd7L4Hp65KhaX1KkdTtSY_NXx4rQphS"],"bt":"0","b":["DPOIlcZk_GLVCVtG7KLbDQa2a5drXGt09wpaeY93G--1"],"c":[],"a":[]}-AABAADtEDd5x0DRfSlGl99G2V3aiJQlILTMG8LHNbG6V3ticL8r1vMK8-nmhZBhZglI06mVChxc-EkgqWPzPlI2rAwD{"v":"KERI10JSON000160_","t":"rot","d":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"1","p":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","kt":"1","k":["DIgRd-GK29iB-G7tao3-BCdMbUCATveeMrzivmmmM_Nf"],"nt":"1","n":["EBrEok_A-yJGpR9GH_ktdd11x3UR0cHaCg0nzAnYLgGj"],"bt":"0","br":[],"ba":[],"a":[]}-AABAADLgLBVFeCOP8t-sxOWKif-JbQ-PnOz0W7aZCuLPOUEri-OdGXjOV2d3y6-R_SsS2U3toE3TNVJ9UyO5NhBSkkO{"v":"KERI10JSON000160_","t":"rot","d":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"2","p":"EDBBxc3_cczsEld6szaFdmhR3JyOhnYaDCCdo_wDe95p","kt":"1","k":["DGx72gYpAdz0N3br4blkVRRoIASdcBTJaqtLnGI6PXHV"],"nt":"1","n":["EMEVqKOHmF9juqQSmphqjnP24tT__JILJJ2Z4u9QKSUn"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAHF__vhEKj4kn1uW0fdBRS75nyG3uvJuEfcOdnx4sfy2vNirkDLkm6WGluUVDfQ7y9_b2TIaIHLfAoBefjNBkF{"v":"KERI10JSON000160_","t":"rot","d":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"3","p":"ENtkE-NChURiXS5j8ES9GeX9VCqr5PLxilygqUJQ5Wr9","kt":"1","k":["DFXuPGU9uFziSr3uQuDo7yKJFmcyURvTq8YOfLfNHf6r"],"nt":"1","n":["EO3OeLeP4Ux570nxE0cuK76Bn0I2NAyA1artuMiyASJf"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAXiKK5er1d8dlAorz6SVhp6xs33eoEKSn2JZrrUHTFZz4xjIa_Ectg9Jyvs12JkdjkNf3VUQ2GMsnfgBpIkXMB{"v":"KERI10JSON000160_","t":"rot","d":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"4","p":"EP0HwW561f8fXuZdau8FyVoQxYTqADGfp12EnI6-Wl6T","kt":"1","k":["DHkJs10SLaBPMBsPx8X6x4TozQMM8OuAzgj681jYSckq"],"nt":"1","n":["ELRF262pZpt8-UiEX5TSsCFiZ1NmRHkvHIq-M6mFKDw_"],"bt":"0","br":[],"ba":[],"a":[]}-AABAACx23xFm12mxnmA413AJCGK67SF5OHb6hlz6qbZjyWbkAqtmqmo2_SRFHtbSFpZ5yIVObSf_F9yr8sRQ-_pJg0F{"v":"KERI10JSON000160_","t":"rot","d":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"5","p":"EGzDR2bgvFESAlpZ_BiiVrefq6S_Ea7navqFyB8EOu6Q","kt":"1","k":["DOFD9XUnKnAUyn0QjYq0BouHyYjvmHN7T2nnVaxr7VHz"],"nt":"1","n":["EFz-ndoE5OXjvD0-UdQAzepB8zpnfk44HN2h8aWmdnKB"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABKlwj4nLkk8q-1YhxA-NjTJCw6AiqyopKvp-MJgx-FKzgZecMmtGm3q5SLImR8P0evrVGL8-DvI-kF9FzYN5YP{"v":"KERI10JSON000160_","t":"rot","d":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"6","p":"EKlpPRdR6NmMHhJ3XuDt7cuPVkfUy11leY6US9bP3jVx","kt":"1","k":["DMrq2ktTKWxE5jjhDKDOz1T8a4R0ZGsikc7M-p5k-Rzp"],"nt":"1","n":["EKw6XLOELmjxU-N_EDuUQ7v1XfodiBVyf2nU2zaSIe05"],"bt":"0","br":[],"ba":[],"a":[]}-AABAABzuuhSMYnxQVJ-K2lJP2WOfUP-oiQAp1Dm2685U-s-91bQovUHAoMoVFWcq0FnxC8W7rQHLXw-Wgt_-lo34u4H{"v":"KERI10JSON000160_","t":"rot","d":"EBOeYHB245lnMJY4or8FvfCaoYlwMVwE5Hr49VE6uXK8","i":"EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL","s":"7","p":"ELQRtBD0vqZOQRTc_uQ0_WebeSM-xLcIog7QPyCDtANg","kt":"1","k":["DApxTJjlbWOgHIMXR_qrryjCIlLFPqnaSRo2M1FFmp4I"],"nt":"1","n":["EOdAKz4CYF6RFZzs_Chyih7QRgcfcZaJ_G02Y-4lrfHg"],"bt":"0","br":[],"ba":[],"a":[]}-AABAAAmR-tO3N1b7b2ZCZmlaSYmQbgHE0T9wZANzXdezQ2b9XPS0RWJcMfHCtpn3qj0Jxhhij1OfMGPSqtshVtEXsYC"#;
    let mut kell = parse_notice_stream(kel).unwrap().into_iter();
    let ev1 = kell.next().unwrap();
    let ev2 = kell.next().unwrap();
    let ev3 = kell.next().unwrap();
    let ev4 = kell.next().unwrap();
    let ev5 = kell.next().unwrap();

    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let escrow_root = Builder::new().prefix("test-db-escrow").tempdir().unwrap();
    let escrow_db = Arc::new(EscrowDb::new(escrow_root.path()).unwrap());

    // We'll use here default escrow configuration. However, it is possible to
    // use only selected escrow types. For examples checkout tests in
    // `processor/escrow_tests.rs`.
    let (not_bus, (ooo_escrow, _, _, _)) =
        default_escrow_bus(db.clone(), escrow_db, EscrowConfig::default());

    let (processor, storage) = (
        BasicProcessor::new(db.clone(), Some(not_bus)),
        EventStorage::new(db.clone()),
    );

    let id: IdentifierPrefix = "EO8cED9H5XPqBdoVatgBkEuSP8yXic7HtWpkex-9e0sL".parse()?;

    process_notice(ev1, &processor)?;
    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);

    process_notice(ev4.clone(), &processor)?;
    let mut escrowed = ooo_escrow.escrowed_out_of_order.get(&id).unwrap();
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev4.clone()));
    assert!(escrowed.next().is_none());

    process_notice(ev3.clone(), &processor)?;
    let mut escrowed = ooo_escrow.escrowed_out_of_order.get(&id).unwrap();
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev4.clone()));
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev3.clone()));
    assert!(escrowed.next().is_none());

    process_notice(ev5.clone(), &processor)?;
    let mut escrowed = ooo_escrow.escrowed_out_of_order.get(&id).unwrap();
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev4.clone()));
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev3.clone()));
    assert_eq!(escrowed.next().map(|e| Notice::Event(e)), Some(ev5.clone()));
    assert!(escrowed.next().is_none());

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 0);
    // check out of order table
    assert_eq!(
        ooo_escrow.escrowed_out_of_order.get(&id).unwrap().count(),
        3
    );

    process_notice(ev2, &processor)?;

    assert_eq!(storage.get_state(&id).unwrap().unwrap().sn, 4);
    // Check if out of order is empty
    let mut escrowed = ooo_escrow.escrowed_out_of_order.get(&id).unwrap();
    assert!(escrowed.next().is_none());

    Ok(())
}
