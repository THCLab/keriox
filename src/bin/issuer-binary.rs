use futures::future::join_all;

use keri::{
    controller::Controller,
    event::sections::threshold::SignatureThreshold,
    event_parsing::SignedEventData,
    oobi::{LocationScheme, Role, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix},
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use tempfile::Builder;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let event_db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let mut controller = Controller::new(event_db_root.path(), oobi_root.path());

    let witness_prefixes = vec![
        "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE",
        "BZFIYlHDQAHxHH3TJsjMhZFbVR_knDzSc3na_VHBZSBs",
        "BYSUc5ahFNbTaqesfY-6YJwzALaXSx-_Mvbs6y3I74js",
    ]
    .iter()
    .map(|prefix_str| prefix_str.parse::<BasicPrefix>().unwrap())
    .collect::<Vec<_>>();

    let witness_addresses = vec![
        "http://localhost:3232",
        "http://localhost:3234",
        "http://localhost:3235",
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
            Some(SignatureThreshold::Simple(3)),
        )
        .unwrap();

    // send inception event to witness to be able to verify end role message
    // TODO should watcher find kel by itself?
    controller.publish(&witness_prefixes, &icp).await.unwrap();

    // send end role oobi to witness
    join_all(witness_prefixes.into_iter().map(|witness| {
        let end_role_license = controller
            .generate_end_role(
                &IdentifierPrefix::Basic(witness.clone()),
                Role::Witness,
                true,
            )
            .unwrap();
        controller.send_to(
            IdentifierPrefix::Basic(witness),
            Scheme::Http,
            SignedEventData::from(end_role_license).to_cesr().unwrap(),
        )
    }))
    .await;
    println!("\nissuer id: {}", controller.keri.prefix().to_string());

    Ok(())
}
