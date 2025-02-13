use futures::future::join_all;
use keri_core::{
    actor::prelude::SelfAddressingIdentifier,
    database::EventDatabase,
    event_message::signed_event_message::{Message, Notice},
    oobi::Scheme,
    prefix::IdentifierPrefix,
};

use crate::{communication::SendingError, identifier::Identifier};

#[derive(thiserror::Error, Debug)]
pub enum BroadcastingError {
    #[error("Sending error while broadcasting events: {0}")]
    SendingError(#[from] SendingError),
    #[error("There's no event of digest: {digest}")]
    MissingEvent { digest: SelfAddressingIdentifier },
}

impl Identifier {
    /// Send new receipts obtained via [`Self::finalize_query`] to specified witnesses.
    /// Returns number of new receipts sent per witness or first error.
    pub async fn broadcast_receipts(
        &mut self,
        dest_wit_ids: &[IdentifierPrefix],
    ) -> Result<(), BroadcastingError> {
        for witness in dest_wit_ids {
            let sn = self.query_cache.load_published_receipts_sn(witness).unwrap();
            let receipts_to_publish = self.known_events.storage.events_db.get_receipts_nt(
                keri_core::database::QueryParameters::Range { id: self.id.clone(), start: sn as u64, limit: 10 }
            ).unwrap();

            let mut max_sn = 0;
            let receipts_futures = receipts_to_publish.map(|rct| {
                max_sn = rct.body.sn.max(max_sn);
                self.communication
                        .send_message_to(
                            witness.clone(),
                            Scheme::Http,
                            Message::Notice(Notice::NontransferableRct(rct.clone())),
                        )
                        
            });
            join_all(receipts_futures).await;
            self.query_cache.update_last_published_receipt(witness, max_sn).unwrap();
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
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

    use crate::{config::ControllerConfig, controller::Controller, error::ControllerError};

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

        let pk = BasicPrefix::Ed25519(km1.public_key());
        let npk = BasicPrefix::Ed25519(km1.next_public_key());

        let icp_event = controller
            .incept(
                vec![pk],
                vec![npk],
                vec![wit1_location.clone(), wit2_location.clone()],
                2,
            )
            .await
            .unwrap();
        let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(icp_event.as_bytes())?);

        let mut identifier = controller.finalize_incept(icp_event.as_bytes(), &signature)?;

        assert_eq!(identifier.notify_witnesses().await.unwrap(), 1);

        // Querying mailbox to get receipts
        for qry in identifier.query_mailbox(&identifier.id, &[wit1_id.clone(), wit2_id.clone()])? {
            let signature = SelfSigningPrefix::Ed25519Sha512(km1.sign(&qry.encode()?)?);
            let act = identifier
                .finalize_query_mailbox(vec![(qry, signature)])
                .await?;
            assert!(act.is_empty());
        }

        assert_eq!(identifier.notify_witnesses().await?, 0);
        assert!(matches!(
            witness1.witness_data.event_storage.get_kel_messages_with_receipts_all(&identifier.id)?.unwrap().as_slice(),
            [Notice::Event(evt)]
            if matches!(evt.event_message.data.event_data, EventData::Icp(_))
                && matches!(evt.witness_receipts.as_ref().unwrap().len(), 2)
        ));

        Ok(())
    }
}
