use futures::future::join_all;

use keri::{
    controller::Controller,
    event::sections::threshold::SignatureThreshold,
    event_parsing::Attachment,
    oobi::{LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, AttachedSignaturePrefix}, signer::KeyManager, derivation::self_signing::SelfSigning,
};
use serde::{Deserialize, Serialize};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use tempfile::Builder;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let event_db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let mut controller = Controller::new(event_db_root.path(), oobi_root.path());

    let witness_prefixes = vec![
        "BSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA",
        // "BVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI",
        // "BT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8",
    ]
    .iter()
    .map(|prefix_str| prefix_str.parse::<BasicPrefix>().unwrap())
    .collect::<Vec<_>>();


    let witness_addresses = vec![
        "http://localhost:3232",
        // "http://localhost:3234",
        // "http://localhost:3235",
    ];

    // Resolve oobi to know how to find witness
    join_all(
        witness_prefixes
            .iter()
            .zip(witness_addresses.iter())
            .map(|(prefix, address)| {
                let lc = LocationScheme::new(
                    IdentifierPrefix::Basic(prefix.clone()),
                    Scheme::Http,
                    url::Url::parse(address).unwrap(),
                );
                controller.resolve(lc)
            }),
    )
    .await;

    let icp = controller
        .keri
        .incept(
            Some(witness_prefixes.clone()),
            Some(SignatureThreshold::Simple(1)),
        )
        .unwrap();

    // send inception event to witness to be able to verify end role message
    // TODO should watcher find kel by itself?
    controller.publish(&witness_prefixes, &icp).await.unwrap();

    println!("\nissuer id: {}", controller.keri.prefix().to_string());

    #[derive(Serialize, Deserialize)]
    struct BasicAcdc {
        issuer: IdentifierPrefix,
        data: String
    }
    let acdc = BasicAcdc { issuer: controller.keri.prefix().clone(), data: "EjLNcJrUEs8PX0LLFFowS-_e9dpX3SEf3C4U1CdhJFUE".into() };

    let acdc_str = serde_json::to_string(&acdc)?;
    let signature = controller.keri.key_manager().clone().lock().unwrap().sign(&acdc_str.as_bytes()).unwrap();
    let attached_signature = AttachedSignaturePrefix::new(SelfSigning::Ed25519Sha512, signature, 0);

    let event_seal = controller.keri.storage.get_last_establishment_event_seal(controller.keri.prefix()).unwrap().unwrap();
    let att = Attachment::SealSignaturesGroups(vec![(event_seal, vec![attached_signature])]);

    println!("acdc: {}{}", acdc_str, att.to_cesr());

    // Rotate keys
    let rot = controller
        .keri
        .rotate(
            None,
            None,
            None
        )
        .unwrap();

    controller.publish(&witness_prefixes, &rot).await.unwrap();


    Ok(())
}
