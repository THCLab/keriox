pub mod vc_state;

use keri::prefix::IdentifierPrefix;
use said::SelfAddressingIdentifier;

use crate::{
    error::Error,
    event::manager_event::{Config, ManagerEventType, ManagerTelEventMessage},
};

use self::vc_state::TelState;

#[derive(Debug)]
pub enum State {
    Management(ManagerTelState),
    Tel(TelState),
}

#[derive(Default, PartialEq, Eq, Debug)]
pub struct ManagerTelState {
    pub prefix: IdentifierPrefix,
    pub sn: u64,
    pub last: SelfAddressingIdentifier,
    pub issuer: IdentifierPrefix,
    pub backers: Option<Vec<IdentifierPrefix>>,
}

impl ManagerTelState {
    pub fn apply(&self, event: &ManagerTelEventMessage) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let event_content = event.data.clone();
        match event_content.event_type {
            ManagerEventType::Vcp(ref vcp) => {
                if self != &ManagerTelState::default() {
                    Err(Error::EventAlreadySavedError)
                } else {
                    let backers = if vcp.config.contains(&Config::NoBackers) {
                        None
                    } else {
                        Some(vcp.backers.clone())
                    };
                    Ok(ManagerTelState {
                        prefix: event_content.prefix.to_owned(),
                        sn: 0,
                        last: event.digest()?,
                        issuer: vcp.issuer_id.clone(),
                        backers,
                    })
                }
            }
            ManagerEventType::Vrt(ref vrt) => {
                if self.sn + 1 == event_content.sn {
                    if vrt.prev_event.eq(&self.last) {
                        match self.backers {
                            Some(ref backers) => {
                                let mut new_backers: Vec<IdentifierPrefix> = backers
                                    .iter()
                                    .filter(|backer| !backers.contains(backer))
                                    .map(|x| x.to_owned())
                                    .collect();
                                vrt.backers_to_add
                                    .iter()
                                    .for_each(|ba| new_backers.push(ba.to_owned()));
                                Ok(ManagerTelState {
                                    prefix: self.prefix.to_owned(),
                                    sn: self.sn + 1,
                                    last: event.digest()?,
                                    backers: Some(new_backers),
                                    issuer: self.issuer.clone(),
                                })
                            }
                            None => Err(Error::Generic(
                                "Trying to update backers of backerless state".into(),
                            )),
                        }
                    } else {
                        Err(Error::Generic("Previous event doesn't match".to_string()))
                    }
                } else {
                    Err(Error::OutOfOrderError)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {

    use keri::prefix::IdentifierPrefix;

    use crate::{error::Error, event::Event, state::ManagerTelState, tel::event_generator};

    #[test]
    pub fn test_management_tel() -> Result<(), Error> {
        // Test if generated event sequence matches
        let mut state = ManagerTelState::default();
        let issuer_prefix: IdentifierPrefix = "DpE03it33djytuVvXhSbZdEw0lx7Xa-olrlUUSH2Ykvc"
            .parse()
            .unwrap();

        let vcp = event_generator::make_inception_event(
            issuer_prefix.clone(),
            vec![],
            0,
            vec![],
            None,
            None,
        )?;
        if let Event::Management(event) = &vcp {
            state = state.apply(event)?;
        }

        assert_eq!(state.sn, 0);
        assert_eq!(state.issuer, issuer_prefix);
        assert_eq!(state.prefix, vcp.get_prefix());
        assert_eq!(state.last, vcp.get_digest()?);

        let backers_to_add = vec!["EJJR2nmwyYAfSVPzhzS6b5CMZAoTNZH3ULvaU6Z-i0d8"
            .parse()
            .unwrap()];

        let rct =
            event_generator::make_rotation_event(&state, &backers_to_add, &vec![], None, None)?;
        if let Event::Management(event) = &rct {
            state = state.apply(event)?;
        }
        assert_eq!(state.issuer, issuer_prefix);
        assert_eq!(state.sn, 1);
        assert_eq!(state.prefix, rct.get_prefix());
        assert_eq!(state.last, rct.get_digest()?);

        Ok(())
    }
}
