use keri_core::{
    actor::event_generator,
    event_message::cesr_adapter::{parse_event_type, EventType},
    oobi::{Role, Scheme},
    prefix::{IdentifierPrefix, SelfSigningPrefix},
    query::reply_event::{ReplyEvent, ReplyRoute},
};

use crate::identifier::Identifier;

use super::MechanicsError;

impl Identifier {
    /// Generates reply event with `end_role_add` route.
    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, MechanicsError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, true)?
                .encode()?,
        )
        .map_err(|_e| MechanicsError::EventFormatError)
    }

    /// Generates reply event with `end_role_cut` route.
    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, MechanicsError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, false)?
                .encode()?,
        )
        .map_err(|_e| MechanicsError::EventFormatError)
    }

    async fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(), MechanicsError> {
        let (dest_identifier, messages_to_send) =
            self.known_events
                .finalize_add_role(signer_prefix, event, sig)?;
        // TODO: send in one request
        for ev in messages_to_send {
            self.communication
                .send_message_to(&dest_identifier, Scheme::Http, ev)
                .await?;
        }
        Ok(())
    }

    pub async fn finalize_add_watcher(
        &self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        let parsed_event =
            parse_event_type(event).map_err(|_e| MechanicsError::EventFormatError)?;
        match parsed_event {
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => {
                    Ok(self.finalize_add_role(&self.id, rpy, vec![sig]).await?)
                }
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err(MechanicsError::WrongEventTypeError),
            },
            _ => Err(MechanicsError::WrongEventTypeError),
        }
    }
}
