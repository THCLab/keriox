use keri_core::{
    event_message::signed_event_message::{Message, Op},
    oobi::{EndRole, LocationScheme, Oobi, Role},
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyRoute, SignedReply},
};

use crate::{error::ControllerError, known_events::KnownEvents};

impl KnownEvents {
    pub fn save_oobi(&self, reply: &SignedReply) -> Result<(), ControllerError> {
		self.oobi_manager.save_oobi(reply)?;
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
