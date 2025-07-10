use keri_core::{
    event::{
        sections::seal::{EventSeal, Seal},
        KeyEvent,
    },
    event_message::{msg::TypedEvent, EventTypeTag},
    prefix::{IdentifierPrefix, SelfSigningPrefix},
};
use teliox::{
    event::verifiable_event::VerifiableEvent,
    seal::{AttachedSourceSeal, EventSourceSeal},
};

use crate::{error::ControllerError, identifier::Identifier};

use super::MechanicsError;

impl Identifier {
    /// Generate `vcp` event and `ixn` event with  seal to `vcp`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn incept_registry(
        &mut self,
    ) -> Result<(IdentifierPrefix, TypedEvent<EventTypeTag, KeyEvent>), ControllerError> {
        // Create tel
        let tel = self.known_events.tel.clone();

        let vcp = tel.make_inception_event(
            self.id.clone(),
            vec![teliox::event::manager_event::Config::NoBackers],
            0,
            vec![],
        )?;
        let id = vcp.get_prefix();
        let seal = Seal::Event(EventSeal::new(
            vcp.get_prefix(),
            vcp.get_sn(),
            vcp.get_digest()?,
        ));
        let ixn = self.anchor_with_seal(&[seal]).unwrap();
        let source_seal = EventSourceSeal {
            sn: ixn.data.sn,
            digest: ixn.digest()?,
        };

        let verifiable_event = VerifiableEvent {
            event: vcp,
            seal: AttachedSourceSeal { seal: source_seal },
        };

        tel.processor.process(verifiable_event)?;
        self.registry_id = Some(id.clone());

        Ok((id, ixn))
    }

    pub async fn finalize_incept_registry(
        &mut self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        self.finalize_anchor(event, sig).await
    }

    pub async fn notify_backers(&self) -> Result<(), MechanicsError> {
        let to_notify = self.known_events.tel.recently_added_events.get();
        let backers = self.known_events.get_current_witness_list(&self.id)?;
        for backer in backers {
            let location = self
                .known_events
                .get_loc_schemas(&IdentifierPrefix::Basic(backer))
                .unwrap()[0]
                .clone();
            for event in &to_notify {
                self.communication
                    .send_tel_event(event.clone(), location.clone())
                    .await
                    .map_err(|e| MechanicsError::OtherError(e.to_string()))?;
            }
        }
        Ok(())
    }
}
