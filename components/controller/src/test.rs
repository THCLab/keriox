#![cfg(test)]

use std::{collections::HashMap, sync::Arc};

use keri_core::{
    event::event_data::EventData,
    event_message::signed_event_message::Notice,
    oobi::LocationScheme,
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    signer::{CryptoBox, KeyManager},
    transport::test::{TestActorMap, TestTransport},
};
use tempfile::Builder;
use url::Host;
use witness::{WitnessEscrowConfig, WitnessListener};

use super::{error::ControllerError, identifier_controller::IdentifierController, Controller};
use crate::ControllerConfig;

#[async_std::test]
async fn test_2_wit() -> Result<(), ControllerError> {
    use url::Url;
    let root = Builder::new().prefix("test-db").tempdir().unwrap();

    let witness1 = {
        let seed = "AK8F6AAiYDpXlWdj2O5F5-6wNCCNJh2A4XOlqwR_HwwH";
        let witness_root = Builder::new().prefix("test-wit1-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness1/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };
    let witness2 = {
        let seed = "AJZ7ZLd7unQ4IkMUwE69NXcvDO9rrmmRH_Xk3TPu9BpP";
        let witness_root = Builder::new().prefix("test-wit2-db").tempdir().unwrap();
        Arc::new(
            WitnessListener::setup(
                url::Url::parse("http://witness2/").unwrap(),
                witness_root.path(),
                Some(seed.to_string()),
                WitnessEscrowConfig::default(),
            )
            .unwrap(),
        )
    };

    let wit1_id = witness1.get_prefix();
    let wit1_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit1_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://witness1/").unwrap(),
    };
    let wit2_id = witness2.get_prefix();
    let wit2_location = LocationScheme {
        eid: IdentifierPrefix::Basic(wit2_id.clone()),
        scheme: keri_core::oobi::Scheme::Http,
        url: Url::parse("http://witness2/").unwrap(),
    };

    let wit_ids = [
        IdentifierPrefix::Basic(wit1_id.clone()),
        IdentifierPrefix::Basic(wit2_id.clone()),
    ];

    let transport = {
        let mut actors: TestActorMap = HashMap::new();
        actors.insert((Host::Domain("witness1".to_string()), 80), witness1.clone());
        actors.insert((Host::Domain("witness2".to_string()), 80), witness2.clone());
        TestTransport::new(actors)
    };

    let controller = Arc::new(Controller::new(ControllerConfig {
        db_path: root.path().to_owned(),
        transport: Box::new(transport.clone()),
        ..Default::default()
    })?);

    let km1 = CryptoBox::new()?;

    let mut ident_ctl = {
        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(
                vec![pk],
                vec![npk],
                vec![wit1_location.clone(), wit2_location.clone()],
                2,
            )
            .await?;
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let incepted_identifier = controller
            .finalize_inception(icp_event.as_bytes(), &signature)
            .await?;
        IdentifierController::new(incepted_identifier, controller.clone(), None)
    };

    assert_eq!(ident_ctl.notify_witnesses().await?, 1);

    // Querying mailbox to get receipts
    for qry in ident_ctl.query_mailbox(&ident_ctl.id, &[wit1_id.clone(), wit2_id.clone()])? {
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
        let act = ident_ctl.finalize_query(vec![(qry, signature)]).await?;
        assert_eq!(act.len(), 0);
    }

    assert_eq!(ident_ctl.notify_witnesses().await?, 0);
    assert_eq!(ident_ctl.broadcast_receipts(&wit_ids).await?, 2);
    assert_eq!(ident_ctl.broadcast_receipts(&wit_ids).await?, 0);

    assert!(matches!(
        witness1.witness_data.event_storage.get_kel_messages_with_receipts(&ident_ctl.id, None)?.unwrap().as_slice(),
        [Notice::Event(evt), Notice::NontransferableRct(rct)]
        if matches!(evt.event_message.data.event_data, EventData::Icp(_))
            && matches!(rct.signatures.len(), 2)
    ));

    // Force broadcast again to see if witness will accept duplicate signatures
    ident_ctl.broadcasted_rcts.clear();

    assert_eq!(ident_ctl.broadcast_receipts(&wit_ids).await?, 2);
    assert_eq!(ident_ctl.broadcast_receipts(&wit_ids).await?, 0);

    assert!(matches!(
        witness1.witness_data.event_storage.get_kel_messages_with_receipts(&ident_ctl.id, None)?.unwrap().as_slice(),
        [Notice::Event(evt), Notice::NontransferableRct(rct)]
            if matches!(evt.event_message.data.event_data, EventData::Icp(_))
            && matches!(rct.signatures.len(), 3) // TODO: fix witness to not insert duplicate signatures
    ));

    Ok(())
}
