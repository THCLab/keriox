use keri::{
    event_message::signed_event_message::{Message, Op},
    oobi::{EndRole, LocationScheme, Oobi, Role},
    prefix::IdentifierPrefix,
    query::reply_event::ReplyRoute,
};

use crate::{error::ControllerError, Controller};

impl Controller {
    pub async fn resolve_oobi(&self, oobi: Oobi) -> Result<(), ControllerError> {
        match oobi {
            Oobi::Location(loc) => {
                let msgs = self.transport.request_loc_scheme(loc).await?;
                for msg in msgs {
                    self.process(&Message::Op(msg))?;
                }
            }
            Oobi::EndRole(EndRole { cid, role, eid }) => {
                // TODO what if more than one
                let loc = self
                    .get_loc_schemas(&eid)?
                    .get(0)
                    .ok_or(ControllerError::UnknownIdentifierError)?
                    .clone();
                let msgs = self.transport.request_end_role(loc, cid, role, eid).await?;
                for msg in msgs {
                    // TODO This ignore signatures. Add verification.
                    if let Message::Op(Op::Reply(signed_oobi)) = msg {
                        self.oobi_manager.save_oobi(&signed_oobi)?;
                    } else {
                        self.process(&msg)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn get_messagebox_location(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<LocationScheme>, ControllerError> {
        Ok(self
            .oobi_manager
            .get_end_role(id, Role::Messagebox)?
            .into_iter()
            .filter_map(|r| {
                if let ReplyRoute::EndRoleAdd(adds) = r.reply.get_route() {
                    let locations = self
                        .oobi_manager
                        .get_loc_scheme(&adds.eid)
                        .unwrap()
                        .unwrap()
                        .into_iter();
                    Some(locations.filter_map(|rep| {
                        if let ReplyRoute::LocScheme(loc) = rep.data.data {
                            Some(loc)
                        } else {
                            None
                        }
                    }))
                } else {
                    None
                }
            })
            .flatten()
            .collect())
    }

    pub fn get_messagebox_end_role(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Vec<EndRole>, ControllerError> {
        let end_roles = self
            .oobi_manager
            .get_end_role(id, Role::Messagebox)?
            .into_iter()
            .map(|reply| match reply.reply.data.data {
                ReplyRoute::EndRoleAdd(end_role) => end_role,
                _ => todo!(),
            })
            .collect();
        Ok(end_roles)
    }
}
