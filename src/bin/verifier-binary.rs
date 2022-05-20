use futures::future::join_all;

use keri::{
    controller::Controller,
    oobi::{LocationScheme, Scheme},
    prefix::IdentifierPrefix,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use tempfile::Builder;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let event_db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let controller = Controller::new(event_db_root.path(), oobi_root.path());

    let watcher_prefixes = vec!["Bo1r-yOiKo7tZw_NEDM6fHeH4ljnp5FJqb3NNG4dwbig"]
        .iter()
        .map(|prefix_str| prefix_str.parse::<IdentifierPrefix>().unwrap())
        .collect::<Vec<_>>();

    let watcher_addresses = vec!["http://localhost:3236"];

    // Resolve oobi to know how to find watcher
    join_all(
        watcher_prefixes
            .iter()
            .zip(watcher_addresses.iter())
            .map(|(prefix, address)| {
                let lc = LocationScheme::new(
                    prefix.clone(),
                    Scheme::Http,
                    url::Url::parse(address).unwrap(),
                );
                controller.resolve(lc)
            }),
    )
    .await;
    let issuer_id = "EMI1a7MCfDG_BwE4kGTt5K7fmF3pbKHKy4xE-Ajb1u_Y"
        .parse::<IdentifierPrefix>()
        .unwrap();

    let addresses = controller.get_loc_schemas(&watcher_prefixes[0]).unwrap();
    match addresses
        .iter()
        .find(|loc| loc.scheme == Scheme::Http)
        .map(|lc| &lc.url)
    {
        Some(address) => {
            // println!("url: {}", format!("{}query/{}", address, issuer_id));
            let response = reqwest::get(format!("{}query/{}", address, issuer_id))
                .await
                .unwrap()
                .text()
                .await
                .unwrap();

            println!("\ngot response: {}", response);
            // Ok(Some(response))
        }
        _ => (), //Err(anyhow!("No address for scheme {:?}", schema)),
    }
    Ok(())
}
