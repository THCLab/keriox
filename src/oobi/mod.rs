use std::{convert::TryFrom, path::Path};

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    event_message::signed_event_message::Message,
    event_parsing::message::signed_event_stream,
    prefix::IdentifierPrefix,
    processor::notification::Notifier,
    query::reply_event::{bada_logic, ReplyEvent, ReplyRoute, SignedReply},
};

pub mod storage;

use self::{error::Error, storage::OobiStorage};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct LocationScheme {
    pub eid: IdentifierPrefix,
    pub scheme: Scheme,
    pub url: Url,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EndRole {
    pub eid: IdentifierPrefix,
    pub role: Role,
    pub cid: IdentifierPrefix,
}

impl LocationScheme {
    pub fn new(eid: IdentifierPrefix, scheme: Scheme, url: Url) -> Self {
        Self { eid, scheme, url }
    }

    pub fn get_eid(&self) -> IdentifierPrefix {
        self.eid.clone()
    }

    pub fn get_scheme(&self) -> Scheme {
        self.scheme.clone()
    }

    pub fn get_url(&self) -> Url {
        self.url.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Tcp,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Controller,
    Witness,
    Watcher,
}

pub struct OobiManager {
    store: OobiStorage,
}

impl OobiManager {
    pub fn new(oobi_db_path: &Path) -> Self {
        Self {
            store: OobiStorage::new(oobi_db_path).unwrap(),
        }
    }

    /// Checks oobi signer and bada logic. Assumes signatures already
    /// verified.
    pub fn check_oobi_reply(&self, rpy: &SignedReply) -> Result<(), Error> {
        match rpy.reply.get_route() {
            // check if signature was made by oobi creator
            ReplyRoute::LocScheme(lc) => {
                if rpy.signature.get_signer() != lc.get_eid() {
                    return Err(Error::OobiError("Wrong reply message signer".into()));
                };

                if let Some(old_rpy) = self.store.get_last_loc_scheme(&lc.eid, &lc.scheme)? {
                    bada_logic(rpy, &old_rpy)?;
                };
                Ok(())
            }
            ReplyRoute::EndRoleAdd(er) | ReplyRoute::EndRoleCut(er) => {
                if rpy.signature.get_signer() != er.cid {
                    return Err(Error::OobiError("Wrong reply message signer".into()));
                };
                if let Some(old_rpy) = self
                    .store
                    .get_end_role(&er.cid, er.role)?
                    .and_then(|rpys| rpys.last().cloned())
                {
                    bada_logic(rpy, &old_rpy)?;
                };
                Ok(())
            }
            _ => Err(Error::OobiError("Wrong oobi type".into())),
        }
    }

    fn parse_and_save(&self, stream: &str) -> Result<(), Error> {
        let _events = signed_event_stream(stream.as_bytes())
            .map_err(|e| Error::OobiError(e.to_string()))?
            .1
            .into_iter()
            .try_for_each(|sed| {
                let msg = Message::try_from(sed).unwrap();
                match msg {
                    Message::Reply(oobi_rpy) => {
                        self.check_oobi_reply(&oobi_rpy)?;
                        self.store.save_oobi(oobi_rpy)?;
                        Ok(())
                    }
                    _ => Err(Error::OobiError("Wrong reply type".into())),
                }
            })?;
        Ok(())
    }

    pub fn get_oobi(&self, id: &IdentifierPrefix) -> Result<Option<Vec<ReplyEvent>>, Error> {
        Ok(self
            .store
            .get_oobis_for_eid(id)?
            .map(|e_list| e_list.into_iter().map(|e| e.reply).collect()))
    }
}

impl Notifier for OobiManager {
    fn notify(
        &self,
        notification: &crate::processor::notification::Notification,
        _bus: &crate::processor::notification::NotificationBus,
    ) -> Result<(), crate::error::Error> {
        match notification {
            crate::processor::notification::Notification::GotOobi(reply) => {
                // Assumes that signatures were verified.
                self.check_oobi_reply(reply)
                    .map_err(|e| crate::error::Error::SemanticError(e.to_string()))?;
                self.store
                    .save_oobi(reply.clone())
                    .map_err(|e| crate::error::Error::SemanticError(e.to_string()))?;
                Ok(())
            }
            _ => Err(crate::error::Error::SemanticError(
                "Wrong notification".into(),
            )),
        }
    }
}
mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("{0}")]
        OobiError(String),
        #[error("Error while parsing url")]
        UrlParsingError(#[from] url::ParseError),
        #[error("Keri error occured")]
        KeriError(#[from] crate::error::Error),
        #[error(transparent)]
        SledError(#[from] sled::Error),
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        event_parsing::message::signed_event_stream,
        oobi::{error::Error, OobiManager},
        prefix::IdentifierPrefix,
        query::reply_event::ReplyRoute,
    };

    use super::{EndRole, LocationScheme};
    #[test]
    fn test_oobi_deserialize() -> Result<(), Error> {
        let oobi = r#"{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}"#;
        let _o: EndRole = serde_json::from_str(oobi).unwrap();

        let oobi = r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#;
        let _o: LocationScheme = serde_json::from_str(oobi).unwrap();

        Ok(())
    }

    fn setup_oobi_manager() -> OobiManager {
        use std::fs;
        use tempfile::Builder;

        // Create test db and event processor.
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
        fs::create_dir_all(root.path()).unwrap();
        let oobi_root = Builder::new().prefix("oobi-test-db").tempdir().unwrap();
        fs::create_dir_all(oobi_root.path()).unwrap();

        OobiManager::new(oobi_root.path())
    }

    #[test]
    fn test_obi_save() -> Result<(), Error> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg"#; //{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
        let stream = signed_event_stream(body.as_bytes());
        assert_eq!(stream.unwrap().1.len(), 2);

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.store.get_oobis_for_eid(
            &"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(res.is_some());

        assert_eq!(
        res.unwrap().iter().map(|oobi| oobi.reply.get_route()).collect::<Vec<_>>(),
        vec![
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#).unwrap()),
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}"#).unwrap()),
        ]
    );

        Ok(())
    }

    #[test]
    pub fn test_oobi_update() -> Result<(), Error> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"Elxbk-5h8a2PhoserezofHRXEDgAEwhrW0wvhXqyupmY","dt":"2022-04-08T15:00:29.163849+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BezpFQMVxodb7WMUBL4aLeQW1CUTUYbcFNPGohh02cKl7kSajyRZAentI-MkconvyI8-QfaO1in5mexYF-1ZPBg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EfJP2Mkp_2UZJoWoNCWZHMgU7uWMIkzih19Nvit36Cho","dt":"2022-04-08T15:00:29.165103+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BFcwrcL7Hc8HYLSPvzMGAAEn5QyY76QWY1l2RotQqsX01HgDh4UZYU5GpiVY2A-AbsRIsUpfIKnQi7r4dc0o0DA"#; //{"v":"KERI10JSON000116_","t":"rpy","d":"EXhq-JsyKmr7PJq7luQ0Psd1linhiL6yI4iiDStKPYSw","dt":"2022-04-08T15:00:29.166115+00:00","r":"/end/role/add","a":{"cid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","role":"controller","eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BJwAp49PBodHj42HlBoStigxsgGEWmdaMOyaY6_q1msdS5pi66SWFCNuLqPWX6p1YWXDmq97MgKZmTRJ3g7mPCg"#;
        let body2 = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EhmRb98IbAp7xqttLe-knTcT0pg5xbkFdU-D8FMi2NTE","dt":"2022-04-08T15:02:55.382713+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BQ2LHGCoTDzGTU4qnAKvnZocjUEwWfpILfngi5Ej3z_7SGJ5q4ciQSZ2uyBONGNqDeOsyrI4vV5LvrQUxg0vLCg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EQqXdsemACUttgKUOiCYTs9JyXIjbio1itQdA2TeKF0I","dt":"2022-04-08T15:02:55.384117+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BD1uIyxgm1MFqhkwlbwarxOdNghWIrs_ClHLrHVj-qpGpS2cM1T1Y8E3GUsfvpsvkHNWUFCBZmaQHoSI4WE2cAw"#; //{"v":"KERI10JSON000116_","t":"rpy","d":"E2P4sXDFiU5MnLCk7pMm7IHWOu9UNrqLqnKZJWjdcvuo","dt":"2022-04-08T15:02:55.385191+00:00","r":"/end/role/add","a":{"cid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","role":"controller","eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0B66IhoBb_nIQjY6wlNHwZHicm2Yf4Ioxbm5cnfSvPLQHFjhE7ROXTDlNfZIjyXMmmboHRtpLrCfHO5kz90PF6CA"#;

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.store.get_oobis_for_eid(
            &"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(res.is_some());
        // Save timestamps of last accepted oobis.
        let timestamps = res
            .clone()
            .unwrap()
            .iter()
            .map(|reply| reply.reply.get_timestamp())
            .collect::<Vec<_>>();

        assert_eq!(
        res.unwrap().iter().map(|oobi| oobi.reply.get_route()).collect::<Vec<_>>(),
        vec![
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
        ]
    );

        // process the same oobis but with new timestamp
        oobi_manager.parse_and_save(body2)?;

        let res = oobi_manager.store.get_oobis_for_eid(
            &"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(res.is_some());
        // Save timestamps of last accepted oobis.
        let timestamps2 = res
            .clone()
            .unwrap()
            .iter()
            .map(|reply| reply.reply.get_timestamp())
            .collect::<Vec<_>>();

        // The same oobis should be in database.
        assert_eq!(
        res.unwrap().iter().map(|oobi| oobi.reply.get_route()).collect::<Vec<_>>(),
        vec![
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
            ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
        ]
    );
        // But timestamps should be updated.
        assert_ne!(timestamps, timestamps2);

        Ok(())
    }
}
