
use keri_controller::{BasicPrefix, LocationScheme};

pub fn first_witness_data() -> (BasicPrefix, LocationScheme) {
    let first_witness_id: BasicPrefix = "BDg3H7Sr-eES0XWXiO8nvMxW6mD_1LxLeE1nuiZxhGp4"
        .parse()
        .unwrap();
    // OOBI (Out-Of-Band Introduction) specifies the way how actors can be found.
    let first_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness2.sandbox.argo.colossi.network/"}}"#,
        first_witness_id
    ))
    .unwrap();
    (first_witness_id, first_witness_oobi)
}

pub fn second_witness_data() -> (BasicPrefix, LocationScheme) {
    let second_witness_id: BasicPrefix = "BDg1zxxf8u4Hx5IPraZzmStfSCZFZbDzMHjqVcFW5OfP"
        .parse()
        .unwrap();
    let second_witness_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://witness3.sandbox.argo.colossi.network/"}}"#,
        second_witness_id
    ))
    .unwrap();
    (second_witness_id, second_witness_oobi)
}

pub fn watcher_data() -> (BasicPrefix, LocationScheme) {
    let watcher_id: BasicPrefix = "BF2t2NPc1bwptY1hYV0YCib1JjQ11k9jtuaZemecPF5b"
        .parse()
        .unwrap();
    let watcher_oobi: LocationScheme = serde_json::from_str(&format!(
        r#"{{"eid":{:?},"scheme":"http","url":"http://watcher.sandbox.argo.colossi.network/"}}"#,
        watcher_id
    ))
    .unwrap();
    (watcher_id, watcher_oobi)
}
