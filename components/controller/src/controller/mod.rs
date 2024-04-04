use std::sync::Arc;

use keri_core::{event_message::signature::Signature, oobi::LocationScheme, prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix}};

use crate::{communication::Communication, config::ControllerConfig, error::ControllerError, identifier::Identifier, known_events::KnownEvents};
pub mod verifying;

pub struct Controller {
	known_events: Arc<KnownEvents>,
	communication: Arc<Communication>,
}

impl Controller {
	pub fn new(config: ControllerConfig) -> Result<Self, ControllerError> {
		let ControllerConfig {
            db_path,
            initial_oobis,
            escrow_config,
            transport,
            tel_transport,
        } = config;

		let events = Arc::new(KnownEvents::new(db_path, escrow_config)?);
		let comm = Arc::new(Communication { events: events.clone(), transport, tel_transport });
		 
		let controller = Self { known_events: events.clone(), communication: comm };
		if !initial_oobis.is_empty() {
            async_std::task::block_on(controller.setup_witnesses(&initial_oobis))?;
        }
		Ok(controller)
	}

	pub async fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
        witnesses: Vec<LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String, ControllerError> {
        self.setup_witnesses(&witnesses).await?;
        self.known_events.incept(public_keys, next_pub_keys, witnesses, witness_threshold)
    }

    pub fn finalize_incept(&self,
        event: &[u8],
        sig: &SelfSigningPrefix) -> Result<Identifier, ControllerError> {
        let initialized_id = self.known_events.finalize_inception(event, sig)?;
        Ok(Identifier::new(initialized_id, self.known_events.clone(), self.communication.clone() ))
    }

	async fn setup_witnesses(&self, oobis: &[LocationScheme]) -> Result<(), ControllerError> {
        for lc in oobis {
            self.communication.resolve_loc_schema(lc).await?;
        }
        Ok(())
    }

    pub fn get_kel_with_receipts(&self, id: &IdentifierPrefix) -> Option<Vec<keri_core::event_message::signed_event_message::Notice>> {
        self.known_events.find_kel_with_receipts(id)
    }

    pub fn verify(&self, data: &[u8], signature: &Signature 
        ) -> Result<(), ControllerError> {
        self.known_events.verify(data, signature)
    }
}