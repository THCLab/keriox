use keri_core::{
    actor::prelude::SelfAddressingIdentifier, error::Error, event_message::{
        signature::Nontransferable,
        signed_event_message::{Message, Notice, SignedNontransferableReceipt},
    }, oobi::Scheme, prefix::{BasicPrefix, IdentifierPrefix}
};

use crate::communication::SendingError;

use super::Identifier;
#[derive(thiserror::Error, Debug)]
pub enum BroadcastingError {
    #[error("Sending error while broadcasting events: {0}")]
    SendingError(#[from] SendingError),
    #[error("There's no event of digest: {digest}")]
    MissingEvent {digest: SelfAddressingIdentifier}
}


impl Identifier {
    /// Send new receipts obtained via [`Self::finalize_query`] to specified witnesses.
    /// Returns number of new receipts sent per witness or first error.
    pub async fn broadcast_receipts(
        &mut self,
        dest_wit_ids: &[IdentifierPrefix],
    ) -> Result<usize, BroadcastingError> {
        let receipts = self
            .known_events
            .storage
            .db
            .get_receipts_nt(&self.id)
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        let mut n = 0;

        for rct in receipts {
            let rct_digest = rct.body.receipted_event_digest.clone();
            let rct_wit_ids = self.get_wit_ids_of_rct(&rct).map_err(|_e| BroadcastingError::MissingEvent { digest: rct_digest.clone() })?;

            for dest_wit_id in dest_wit_ids {
                // Don't send receipt to witness who created it.
                // TODO: this only works if the target witness ID is a BasicPrefix.
                if let IdentifierPrefix::Basic(dest_wit_id) = dest_wit_id {
                    if rct_wit_ids.contains(dest_wit_id) {
                        continue;
                    }
                }

                // Don't send the same receipt twice.
                if rct_wit_ids.iter().all(|rct_wit_id| {
                    self.broadcasted_rcts.contains(&(
                        rct_digest.clone(),
                        rct_wit_id.clone(),
                        dest_wit_id.clone(),
                    ))
                }) {
                    continue;
                }

                self.communication
                    .send_message_to(
                        dest_wit_id,
                        Scheme::Http,
                        Message::Notice(Notice::NontransferableRct(rct.clone())),
                    )
                    .await?;

                // Remember event digest and witness ID to avoid sending the same receipt twice.
                for rct_wit_id in &rct_wit_ids {
                    self.broadcasted_rcts.insert((
                        rct_digest.clone(),
                        rct_wit_id.clone(),
                        dest_wit_id.clone(),
                    ));
                }

                n += 1;
            }
        }

        Ok(n)
    }

    /// Get IDs of witnesses who signed given receipt.
    fn get_wit_ids_of_rct(
        &self,
        rct: &SignedNontransferableReceipt,
    ) -> Result<Vec<BasicPrefix>, Error> {
        let mut wit_ids = Vec::new();
        for sig in &rct.signatures {
            match sig {
                Nontransferable::Indexed(sigs) => {
                    for sig in sigs {
                        let wits = self.known_events.storage.get_witnesses_at_event(
                            rct.body.sn,
                            &self.id,
                            &rct.body.receipted_event_digest,
                        )?;
                        wit_ids.push(wits[sig.index.current() as usize].clone());
                    }
                }
                Nontransferable::Couplet(sigs) => {
                    for (wit_id, _sig) in sigs {
                        wit_ids.push(wit_id.clone());
                    }
                }
            }
        }
        Ok(wit_ids)
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

    use crate::{
        config::ControllerConfig, controller::Controller, error::ControllerError,
    };

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
            witness1.witness_data.event_storage.get_kel_messages_with_receipts(&identifier.id, None)?.unwrap().as_slice(),
            [Notice::Event(evt), Notice::NontransferableRct(rct)]
            if matches!(evt.event_message.data.event_data, EventData::Icp(_))
                && matches!(rct.signatures.len(), 2)
        ));

        // Force broadcast again to see if witness will accept duplicate signatures
        identifier.broadcasted_rcts.clear();

        assert_eq!(identifier.broadcast_receipts(&wit_ids).await.unwrap(), 2);
        assert_eq!(identifier.broadcast_receipts(&wit_ids).await.unwrap(), 0);

        assert!(matches!(
            witness1.witness_data.event_storage.get_kel_messages_with_receipts(&identifier.id, None)?.unwrap().as_slice(),
            [Notice::Event(evt), Notice::NontransferableRct(rct)]
                if matches!(evt.event_message.data.event_data, EventData::Icp(_))
                && matches!(rct.signatures.len(), 3) // TODO: fix witness to not insert duplicate signatures
        ));

        Ok(())
    }
}
