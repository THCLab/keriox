use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use strum::{Display, EnumString};
use url::Url;

use crate::{
    event::EventMessage,
    event_message::signed_event_message::Message,
    event_parsing::message::signed_event_stream,
    keri::Responder,
    prefix::{IdentifierPrefix, Prefix},
    processor::validator::EventValidator,
    query::{
        reply_event::{bada_logic, ReplyEvent, SignedReply},
        Route,
    },
};

pub mod storage;

use self::{error::Error, storage::OobiStorage};

pub type ReplyOobiEvent = EventMessage<ReplyEvent<Oobi>>;

impl ReplyOobiEvent {
    pub fn get_oobi(&self) -> Oobi {
        self.event.content.data.data.clone()
    }
}
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Oobi {
    eid: IdentifierPrefix,
    scheme: Scheme,
    url: Url,
}

impl Oobi {
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

impl TryFrom<url::Url> for Oobi {
    type Error = Error;

    fn try_from(url: url::Url) -> Result<Self, Self::Error> {
        let scheme = Scheme::try_from(url.scheme())
            .map_err(|e| Error::OobiError(format!("Wrong scheme: {}", e)))?;
        let url_address = Url::parse(&format!(
            "{}://{}:{:?}",
            url.scheme(),
            url.host_str()
                .ok_or_else(|| Error::OobiError("Wrong host".into()))?,
            url.port()
                .ok_or_else(|| Error::OobiError("Wrong port".into()))?
        ))?;
        let mut path_iterator = url
            .path_segments()
            .ok_or_else(|| Error::OobiError("No identifier prefix".into()))?;
        // skip oobi string
        path_iterator.next();
        let eid = path_iterator
            .next()
            .ok_or_else(|| Error::OobiError("No identifier prefix".into()))?
            .parse::<IdentifierPrefix>()
            .map_err(|e| Error::OobiError(format!("Wrong identifier prefix: {}", e)))?;

        Ok(Self {
            eid,
            scheme,
            url: url_address,
        })
    }
}

impl TryFrom<Oobi> for url::Url {
    type Error = Error;
    fn try_from(oobi: Oobi) -> Result<Self, Self::Error> {
        url::Url::parse(&format!("{}oobi/{}", oobi.url, oobi.eid.to_str())).map_err(|e| e.into())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, EnumString, Display)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum Scheme {
    Http,
    Tcp,
}

pub struct OobiManager {
    validator: EventValidator,
    store: OobiStorage,
    queue: Responder<String>,
}

impl OobiManager {
    pub fn new(validator: EventValidator) -> Self {
        Self {
            validator,
            store: OobiStorage::new(),
            queue: Responder::default(),
        }
    }

    // TODO maybe this should be in reply module?
    pub fn check_oobi_reply(&self, rpy: &SignedReply<Oobi>) -> Result<(), Error> {
        let route = rpy.reply.event.get_route();
        // check if signature was made by ksn creator
        let oobi_id = rpy.reply.event.content.data.data.eid.clone();
        if let Route::ReplyOobi = route {
            if rpy.signature.get_signer() != oobi_id {
                return Err(Error::OobiError("Wrong reply message signer".into()));
            };
            // check signature
            self.validator
                .verify(&rpy.reply.serialize()?, &rpy.signature)?;
            // check digest
            rpy.reply.check_digest()?;

            // check bada logic
            if let Some(old_rpy) = self.store.get(&oobi_id)? {
                bada_logic(rpy, &old_rpy)?;
            }
        };

        Ok(())
    }

    pub fn process_oobi(&self, oobi_str: &str) -> Result<(), Error> {
        self.queue
            .append(oobi_str.to_string())
            .map_err(|e| Error::OobiError(e.to_string()))
    }

    fn parse_and_save(&self, stream: &str) -> Result<(), Error> {
        let _events = signed_event_stream(stream.as_bytes())
            .map_err(|e| Error::OobiError(e.to_string()))?
            .1
            .into_iter()
            .try_for_each(|sed| {
                let msg = Message::try_from(sed).unwrap();
                match msg {
                    Message::SignedOobi(oobi_rpy) => {
                        match self.check_oobi_reply(&oobi_rpy) {
                            Ok(_) => {
                                self.store.save(oobi_rpy);
                                Ok(())
                            } // add to db,
                            Err(_) => Err(Error::OobiError("Obi validation error".into())),
                        }
                    }
                    _ => Err(Error::OobiError("Wrong reply type".into())),
                }
            })?;
        Ok(())
    }

    /// Check oobi and saves
    pub async fn load(&self) -> Result<(), Error> {
        while let Some(oobi) = self.queue.get_data_to_respond() {
            let resp = reqwest::get(oobi.clone())
                .await
                .map_err(|e| Error::OobiError(e.to_string()))?
                .text()
                .await
                .map_err(|e| Error::OobiError(e.to_string()))?;
            self.parse_and_save(&resp)?;
        }
        Ok(())
    }

    pub fn get_oobi(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<EventMessage<ReplyEvent<Oobi>>>, Error> {
        Ok(self.store.get(id)?.map(|e| e.reply))
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
    }
}

#[test]
pub fn test_oobi_from_url() {
    let oobi_url = "http://127.0.0.1:3232/oobi/BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE";
    let oobi = Oobi::try_from(url::Url::parse(oobi_url).unwrap()).unwrap();
    assert_eq!(
        oobi.eid.to_str(),
        "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE"
    );
    assert_eq!(oobi.scheme, Scheme::Http);
    assert_eq!(oobi.url.to_string(), "http://127.0.0.1:3232/");
}

#[test]
fn test_oobi_deserialize() -> Result<(), Error> {
    let body = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let stream = signed_event_stream(body);
    assert_eq!(stream.unwrap().1.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_obi_save() -> Result<(), Error> {
    use crate::database::sled::SledEventDatabase;
    use std::{fs, sync::Arc};
    let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let stream = signed_event_stream(body.as_bytes());
    assert_eq!(stream.unwrap().1.len(), 2);

    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let validator = EventValidator::new(Arc::clone(&db));

    let oobi_manager = OobiManager::new(validator);

    oobi_manager.parse_and_save(body)?;
    // oobi_manager.process_oobi(
    //     "http://127.0.0.1:5643/oobi/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw/controller",
    // )?;
    // oobi_manager.load().await?;
    let res = oobi_manager.store.get(
        &"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"
            .parse::<IdentifierPrefix>()
            .unwrap(),
    )?;
    assert!(res.is_some());

    Ok(())
}
