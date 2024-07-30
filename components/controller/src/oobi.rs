use keri_core::{
    oobi::{EndRole, LocationScheme, Role},
    prefix::IdentifierPrefix,
    query::reply_event::ReplyRoute,
};

use crate::{error::ControllerError, identifier::Identifier, known_events::OobiRetrieveError};

impl Identifier {
    pub fn get_location(
        &self,
        identifier: &IdentifierPrefix,
    ) -> Result<Vec<LocationScheme>, OobiRetrieveError> {
        self.known_events.get_loc_schemas(identifier)
    }

    pub fn get_role_location(
        &self,
        id: &IdentifierPrefix,
        role: Role,
    ) -> Result<Vec<LocationScheme>, ControllerError> {
        Ok(self
            .known_events
            .oobi_manager
            .get_end_role(id, role)?
            .unwrap_or_default()
            .into_iter()
            .filter_map(|r| {
                if let ReplyRoute::EndRoleAdd(adds) = r.reply.get_route() {
                    let locations = self
                        .known_events
                        .oobi_manager
                        .get_loc_scheme(&adds.eid)
                        .unwrap_or_default()
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

    pub fn get_end_role(
        &self,
        id: &IdentifierPrefix,
        role: Role,
    ) -> Result<Vec<EndRole>, ControllerError> {
        let end_roles = self
            .known_events
            .oobi_manager
            .get_end_role(id, role)?
            .unwrap_or_default()
            .into_iter()
            .map(|reply| match reply.reply.data.data {
                ReplyRoute::EndRoleAdd(end_role) => end_role,
                _ => todo!(),
            })
            .collect();
        Ok(end_roles)
    }
}
