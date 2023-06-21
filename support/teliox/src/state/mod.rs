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
                    Err(Error::Generic("Improper manager state".into()))
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
