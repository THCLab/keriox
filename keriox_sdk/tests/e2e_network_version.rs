//! A client writes KERI 2.0 once every witness and watcher it uses does:
//! operators switch the servers, and clients follow what they report.

mod common;

use keri_core::event_message::keri_version::KeriVersion;
use keri_sdk::advanced::{agreed_keri_version, server_keri_version};
use url::Url;

fn url(base: &str) -> Url {
    Url::parse(base).unwrap()
}

#[actix_rt::test]
async fn clients_write_keri_2_once_every_server_does() {
    let old_witness = common::spawn_witness();
    let witness = common::spawn_witness_writing(KeriVersion::V2_0);
    let watcher = common::spawn_watcher_writing(KeriVersion::V2_0);

    assert_eq!(
        server_keri_version(&url(&old_witness.url)).await.unwrap(),
        KeriVersion::V1_0
    );
    assert_eq!(
        server_keri_version(&url(&witness.url)).await.unwrap(),
        KeriVersion::V2_0
    );

    let switched = [url(&witness.url), url(&watcher.url)];
    assert_eq!(agreed_keri_version(&switched).await, KeriVersion::V2_0);

    // One server still on 1.0, or one that cannot be reached, holds it.
    let mixed = [url(&witness.url), url(&old_witness.url)];
    assert_eq!(agreed_keri_version(&mixed).await, KeriVersion::V1_0);
    let unreachable = [url(&watcher.url), url("http://127.0.0.1:9/")];
    assert_eq!(agreed_keri_version(&unreachable).await, KeriVersion::V1_0);
    assert_eq!(agreed_keri_version(&[]).await, KeriVersion::V1_0);
}
