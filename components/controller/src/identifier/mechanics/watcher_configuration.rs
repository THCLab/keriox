use keri_core::{
    actor::event_generator,
    database::{EscrowCreator, EventDatabase},
    event_message::cesr_adapter::{parse_event_type, EventType},
    oobi::{Role, Scheme},
    oobi_manager::storage::OobiStorageBackend,
    prefix::{IdentifierPrefix, SelfSigningPrefix},
    query::reply_event::{ReplyEvent, ReplyRoute},
};
use teliox::database::TelEventDatabase;

use crate::identifier::Identifier;

use super::MechanicsError;

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: TelEventDatabase + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Generates reply event with `end_role_add` route.
    pub fn add_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, MechanicsError> {
        self.add_role(watcher_id, Role::Watcher)
    }

    /// Generate an `end_role_add` reply authorizing `eid` for `role`. The
    /// role-generic form behind [`add_watcher`](Self::add_watcher); callers
    /// that authorize a mailbox endpoint use [`add_messagebox`](Self::add_messagebox).
    pub fn add_role(
        &self,
        eid: IdentifierPrefix,
        role: Role,
    ) -> Result<String, MechanicsError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &eid, role, true).encode()?,
        )
        .map_err(|_e| MechanicsError::EventFormatError)
    }

    /// Generates an `end_role_add` reply naming `messagebox_id` as this
    /// identifier's Messagebox endpoint. Peers resolve this end-role to learn
    /// which server hosts the identifier's mailbox (cross-server routing).
    pub fn add_messagebox(
        &self,
        messagebox_id: IdentifierPrefix,
    ) -> Result<String, MechanicsError> {
        self.add_role(messagebox_id, Role::Messagebox)
    }

    /// Generates reply event with `end_role_cut` route.
    pub fn remove_watcher(&self, watcher_id: IdentifierPrefix) -> Result<String, MechanicsError> {
        String::from_utf8(
            event_generator::generate_end_role(&self.id, &watcher_id, Role::Watcher, false)
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
                .send_message_to(dest_identifier.clone(), Scheme::Http, ev)
                .await?;
        }
        Ok(())
    }

    pub async fn finalize_add_watcher(
        &self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(), MechanicsError> {
        self.finalize_add_end_role(event, sig).await
    }

    /// Sign and deliver a signed `end_role_add` reply, whatever the role.
    /// `finalize_add_watcher` is the historical name for this route-generic
    /// operation; `finalize_add_end_role` reads honestly for non-watcher
    /// roles (e.g. Messagebox). Both share the same body.
    pub async fn finalize_add_end_role(
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
