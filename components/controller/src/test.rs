#[cfg(feature = "wallet")]
use universal_wallet::prelude::UnlockedWallet;

use keri::event_parsing::attachment;
#[cfg(test)]
use keri::{database::sled::SledEventDatabase, error::Error};

use std::sync::{Arc, Mutex};

use crate::controller::Controller;

#[test]
fn interop() -> Result<(), Error> {
    use keri::event_parsing::Attachment;
    let issuer_kel_str = br#"{"v":"KERI10JSON0001b7_","t":"icp","d":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"0","kt":"1","k":["DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"],"nt":"1","n":["Eao8tZQinzilol20Ot-PPlVz6ta8C4z-NpDOeVs63U8s"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAA0EpZtBNLxOIncUDeLgwX3trvDXFA5adfjpUwb21M5HWwNuzBMFiMZQ9XqM5L2bFUVi6zXomcYuF-mR7CFpP8DQ-BADAAWUZOb17DTdCd2rOaWCf01ybl41U7BImalPLJtUEU-FLrZhDHls8iItGRQsFDYfqft_zOr8cNNdzUnD8hlSziBwABmUbyT6rzGLWk7SpuXGAj5pkSw3vHQZKQ1sSRKt6x4P13NMbZyoWPUYb10ftJlfXSyyBRQrc0_TFqfLTu_bXHCwACKPLkcCa_tZKalQzn3EgZd1e_xImWdVyzfYQmQvBpfJZFfg2c-sYIL3zl1WHpMQQ_iDmxLSmLSQ9jZ9WAjcmDCg-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c16d643400p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"1","p":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":[{"i":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM","s":"0","d":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}]}-VBq-AABAAZZlCpwL0QwqF-eTuqEgfn95QV9S4ruh4wtxKQbf1-My60Nmysprv71y0tJGEHkMsUBRz0bf-JZsMKyZ3N8m7BQ-BADAA6ghW2PpLC0P9CxmW13G6AeZpHinH-_HtVOu2jWS7K08MYkDPrfghmkKXzdsMZ44RseUgPPty7ZEaAxZaj95bAgABKy0uBR3LGMwg51xjMZeVZcxlBs6uARz6quyl0t65BVrHX3vXgoFtzwJt7BUl8LXuMuoM9u4PQNv6yBhxg_XEDwACJe4TwVqtGy1fTDrfPxa14JabjsdRxAzZ90wz18-pt0IwG77CLHhi9vB5fF99-fgbYp2Zoa9ZVEI8pkU6iejcDg-EAB0AAAAAAAAAAAAAAAAAAAAAAQ1AAG2022-04-11T20c50c22d909900p00c00{"v":"KERI10JSON00013a_","t":"ixn","d":"EPYT0dEpoc_5QKIGnRYFRqpXHGpeYOhveJTmHoVC6LMU","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","s":"2","p":"Ek48ahzTIUA1ynJIiRd3H0WymilgqDbj8zZp4zzrad-w","a":[{"i":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"0","d":"EQ6RIFoVUDmmyuoMDMPPHDm14GtXaIf98j4AG2vNfZ1U"}]}-VBq-AABAAYycRM_VyvV2fKyHdUceMcK8ioVrBSixEFqY1nEO9eTZQ2NV8hrLc_ux9_sKn1p58kyZv5_y2NW3weEiqn-5KAA-BADAAQl22xz4Vzkkf14xsHMAOm0sDkuxYY8SAgJV-RwDDwdxhN4WPr-3Pi19x57rDJAE_VkyYwKloUuzB5Dekh-JzCQABk98CK_xwG52KFWt8IEUU-Crmf058ZJPB0dCffn-zjiNNgjv9xyGVs8seb0YGInwrB351JNu0sMHuEEgPJLKxAgACw556h2q5_BG6kPHAF1o9neMLDrZN_sCaJ-3slWWX-y8M3ddPN8Zp89R9A36t3m2rq-sbC5h_UDg5qdnrZ-ZxAw-EAB0AAAAAAAAAAAAAAAAAAAAAAg1AAG2022-04-11T20c50c23d726188p00c00"#;
    let holder_kel_str = br#"{"v":"KERI10JSON0001b7_","t":"icp","d":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","i":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","s":"0","kt":"1","k":["DaUjZzbtZLpCZUrRUqA0LZIC83_Gbsj2BHMEOe7ChMsc"],"nt":"1","n":["EKxpiBfmvUwo_H_YT9-PsPjTZysUgiRE_OFs_pwvM9RU"],"bt":"3","b":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"c":[],"a":[]}-VBq-AABAAPNPcy7cftbCQRZtBE4RAIrSKGUfLweG0UoBN4636GU4O2qHck8zgFblSDALJ5YRGjMZxAZZbhqGJLS43zsFaBw-BADAAei_IOwg71UvnTiY_Z8ewWJTpWAd9F2aBOQBC7QKLkLfGC62scI1rpc0mBeXE6GKoP0KWs5IpMSN_MsxatxkWCwABajaJSa6vSdGO834ci5QPuYeQBRBvIs31ZyYI2LigyYO-bQEqx3NR4ODUGonndBFT6e6CdZdtUkf4CyNEbMrQCAACEpMn2CQ7FrxBXVIPCkERvRr1o41AaJFw9RGqA-uAsvcXSlaJ8JHwnYcdvuHTigYAFHn8PTAqBl3kjLo5ZWehDA-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c18d709371p00c00"#;
    let _witness1 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Eie2UH5m4ti4QNAa4Yct8ISFVtHBNKjX7gJ0ZEc_IBIM","i":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","s":"0","kt":"1","k":["Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAgMfAHPyZHqGvBMrASQ7j8LMelEVjZaUdtfdQJKjvayrXxdtF6ZpolH6WD2efVNStyWLCstgn1dVolzqN9Wf2Bw-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c12d027186p00c00"#;
    let _witness2 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Ez7jRMWuy9UWweIF3RkLHecF7yH2jGceWqQYMDhyEECU","i":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","s":"0","kt":"1","k":["BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAtMr9S7-k6zJr7-nmI0R_uCR189M_a09b2bDGOMbyFCmI6CZd76wKULESRFcHqpKYMRaJzj6Nqghceh4dxT_zAw-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c11d949552p00c00"#;
    let _witness3 = br#"{"v":"KERI10JSON0000fd_","t":"icp","d":"Erch8-EoKKuPgwH_O90xzU44DIx-hi6Yq_0yC7PZG0RQ","i":"BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo","s":"0","kt":"1","k":["BGKVzj4ve0VSd8z_AmvhLg4lqcC_9WYX90k03q-R_Ydo"],"nt":"0","n":[],"bt":"0","b":[],"c":[],"a":[]}-VAn-AABAAet3jlqpjTnkIrUUu8MqDmJSejeOSsHnfhyLR9gUHOiemBX0FqDatVQzzisXcXSW3E9Bys4_Oj7OBoczLTSwUBA-EAB0AAAAAAAAAAAAAAAAAAAAAAA1AAG2022-04-11T20c50c11d870386p00c00"#;

    use tempfile::Builder;
    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let alice_db = Arc::new(SledEventDatabase::new(root.path()).unwrap());

    let alice_key_manager = Arc::new(Mutex::new({
        use keri::signer::CryptoBox;
        CryptoBox::new()?
    }));

    // Init controller.
    let controller = Controller::new(
        Arc::clone(&alice_db),
        Arc::clone(&alice_key_manager),
        oobi_root.path(),
    )?;

    controller.parse_and_process(issuer_kel_str)?;
    let state = controller
        .get_state_for_prefix(
            &"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M"
                .parse()
                .unwrap(),
        )
        .unwrap()
        .unwrap();

    assert_eq!(state.sn, 2);
    let pk = state.current.public_keys;

    assert_eq!(
        pk[0],
        "DruZ2ykSgEmw2EHm34wIiEGsUa_1QkYlsCAidBSzUkTU"
            .parse()
            .unwrap()
    );

    controller.parse_and_process(holder_kel_str)?;
    let pk = controller
        .get_state_for_prefix(
            &"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI"
                .parse()
                .unwrap(),
        )
        .unwrap()
        .unwrap()
        .current
        .public_keys;

    assert_eq!(
        pk[0],
        "DaUjZzbtZLpCZUrRUqA0LZIC83_Gbsj2BHMEOe7ChMsc"
            .parse()
            .unwrap()
    );

    let credential = br#"{"v":"ACDC10JSON00019e_","d":"EzSVC7-SuizvdVkpXmHQx5FhUElLjUOjCbgN81ymeWOE","s":"EWCeT9zTxaZkaC_3-amV2JtG6oUxNA36sCC0P5MI7Buw","i":"Ew-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M","a":{"d":"EbFNz3vOMBbzp5xmYRd6rijvq08DCe07bOR-DA5fzO6g","i":"EeWTHzoGK_dNn71CmJh-4iILvqHGXcqEoKGF4VUc6ZXI","dt":"2022-04-11T20:50:23.722739+00:00","LEI":"5493001KJTIIGC8Y1R17"},"e":{},"ri":"EoLNCdag8PlHpsIwzbwe7uVNcPE1mTr-e1o9nCIDPWgM"}"#;
    let sign = br#"-FABEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M0AAAAAAAAAAAAAAAAAAAAAAAEw-o5dU5WjDrxDBK4b4HrF82_rYb6MX6xsegjq4n0Y7M-AABAAKcvAE-GzYu4_aboNjC0vNOcyHZkm5Vw9-oGGtpZJ8pNdzVEOWhnDpCWYIYBAMVvzkwowFVkriY3nCCiBAf8JDw"#;
    let sig = attachment::attachment(sign).unwrap().1;
    if let Attachment::SealSignaturesGroups(atts) = sig {
        let keys = atts.iter().map(|(seal, sigs)| {
            controller
                .storage
                .get_keys_at_event(&seal.prefix, seal.sn, &seal.event_digest)
                .unwrap()
                .unwrap()
                .verify(credential, &sigs)
                .unwrap()
        });
        println!("keys: {:?}", keys.collect::<Vec<_>>());
    };

    Ok(())
}
