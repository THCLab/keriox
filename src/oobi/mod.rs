use std::{collections::{HashMap, VecDeque}, convert::TryFrom, sync::Mutex};

use serde::{Deserialize, Serialize};

use crate::{prefix::IdentifierPrefix, event_parsing::message::{signed_event_stream}, query::{reply::{SignedReply, bada_logic, ReplyEvent}, Route}, event_message::signed_event_message::Message, processor::{validator::{EventValidator, self}, notification::{Notifier, Notification, NotificationBus}}, keri::Keri, signer::CryptoBox, event::EventMessage};

use self::error::Error;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Oobi {
    eid: IdentifierPrefix,
    scheme: Scheme,
    url: String,
}

impl Oobi {
    pub fn get_eid(&self) -> IdentifierPrefix {
        self.eid.clone()
    }

    pub fn get_scheme(&self) -> Scheme {
        self.scheme.clone()
    }

    pub fn get_url(&self) -> String {
        self.url.clone()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Tcp,
}

// Helper struct for appending kel events that needs receipt generation.
// Receipts should be then signed and send somewhere.
#[derive(Default)]
pub struct Responder {
    needs_response: Mutex<VecDeque<String>>,
}

impl Responder {
    pub fn get_data_to_respond(&self) -> Option<String> {
        self.needs_response.lock().unwrap().pop_front()
    }

    pub fn append(&self,  oobi: &str) -> Result<(), Error> {
        self.needs_response.lock().unwrap().push_back(oobi.into());
        Ok(())
    }
}

pub struct OobiManager {
    validator: EventValidator,
    store: HashMap<IdentifierPrefix, SignedReply<Oobi>>,
    queue: Responder,
}

impl Notifier for OobiManager {
    fn notify(&self, notification: &Notification, _bus: &NotificationBus) -> Result<(), crate::error::Error> {
        if let Notification::GotOobi(oobi_rpy) = notification {
            let url = oobi_rpy.event.content.data.data.url.clone();
            self.queue.append(&url);

            Ok(())
        } else {
            Err(crate::error::Error::SemanticError("Wrong notification type".into()))
        }
    }
}

impl OobiManager {
    pub fn new(validator: EventValidator) -> Self {
        Self {
            validator,
            store: HashMap::new(),
            queue: Responder::default()
        }
    }

    // TODO maybe this should be in reply module?
    pub fn check_oobi_reply(&self, rpy: &SignedReply<Oobi>) -> Result<(), Error> {
        let route = rpy.reply.event.get_route();
        // check if signature was made by ksn creator
        let oobi_id = rpy.reply.event.content.data.data.eid.clone();
        if let Route::ReplyOobi = route {
            if rpy.signature.get_signer() != oobi_id {
                return Err(Error::OobiError("Wrong reply message signer".into()).into());
            };
            // check signature
            self.validator.verify(&rpy.reply.serialize().unwrap(), &rpy.signature).unwrap();
            // check digest
            rpy.reply.check_digest().unwrap();

            // check bada logic
            match self
                .store
                .get(&oobi_id)
            {
                Some(old_rpy) => {
                    bada_logic(&rpy, &old_rpy).unwrap();
                }
                 // no previous rpy event to compare
                None => (),
            }
        };

        Ok(())
    }

    pub fn process_oobi(&self, oobi_str: &str) -> Result<(), Error> {
        self.queue.append(oobi_str)
    }

    /// Check oobi and saves
     pub async fn load(&mut self) -> Result<(), Error> {
         while let Some(oobi) = self.queue.get_data_to_respond() {
            let resp = reqwest::get(oobi.clone())
                .await
                .unwrap()
                .text()
                .await
                .unwrap();
            let events = signed_event_stream(resp.as_bytes()).unwrap().1
            .into_iter().for_each(|sed| {
                let msg = Message::try_from(sed).unwrap();
                match msg {
                    Message::SignedOobi(oobi_rpy) => {
                        let pref = oobi_rpy.reply.event.content.data.data.eid.clone();
                        match self.check_oobi_reply(&oobi_rpy) {
                            Ok(_) => {
                                self.store.insert(pref, oobi_rpy);
                                Ok(())
                            } // add to db,
                            Err(_) => {Err(Error::OobiError("Obi validation error".into()))},
                        }
                    },
                    _ => Err(Error::OobiError("Wrong reply type".into())),
                }.unwrap();

            });
        }
        Ok(())
    }

    pub fn get_oobi(&self, id: &IdentifierPrefix) -> Option<EventMessage<ReplyEvent<Oobi>>> {
        self.store.get(id).map(|e| e.reply.clone() )
    }
}
mod error {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("{0}")]
        OobiError(String),
    }
}

#[tokio::test]
async fn test() -> Result<(), Error> {
    // let oo = OobiLoader { queue: vec![] };
    // let url = "http://127.0.0.1:5643/oobi/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw/controller";
    // let body = reqwest::get(url).await.unwrap().text().await.unwrap();

    let body = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let body = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"ETdTl68oDvl1OO_FxZfj204a5-_XEF2VzDUdRbiQWs7A","dt":"2022-03-01T14:10:05.090469+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BsZyytWphsJsffUtqAotCy82dMqyGrksbmj_XeTPeIzCMvKH-s7OQzyqEL5vZNhq9VaYpTd_xTPJ7V5uXAcY3AQ{"v":"KERI10JSON0000f8_","t":"rpy","d":"EQP3bOSowsw9xp_umVQYha2bePSBxetx-8EVKlL_6x70","dt":"2022-03-01T14:10:05.091467+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BjFW6aEf57rhJETsUWlftMgsatdoBsQkULOBmZqcMsQ-eQriIjOJtTlZ2qUYiZXiN6Nsy_bc47pGQzlwdlOGeBQ{"v":"KERI10JSON000116_","t":"rpy","d":"EQT2-2Td_FN_HoHE0iZJoBBO_GUPxzy7pPLCT3BWiykE","dt":"2022-03-01T14:10:05.092341+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BY9s2kMpbg-Hx_M909TVa_ov7F0tKcdyobHrtFAcoHufSodGXSXTNbaQQifJ2YS-J4p7u8uieH5QLUYU3SUzAAw"#;

    // let oobi = Oobi {eid: IdentifierPrefix::default(), scheme: Scheme::Http, url: "".to_string()};
    // let rpy = ReplyEvent::new_reply(oobi, Route::ReplyOobi, SelfAddressing::Blake3_256, SerializationFormats::JSON).unwrap();

    // let ggg = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"E4UJUIbHfIcNLWt9dBlBLLlQ4sIll2ZjkcTI4oXkrwKQ","dt":"2022-02-28T15:01:07.492444+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BaRjvmgCbvrLFbv3DyyLU4Eh3gpbakPhiGj32vIbSzo9naursaKwVfeUk1QWG6U0MawvyCCoLADj1gU2hlKrJAQ"#;
    let stream = signed_event_stream(body);
    assert_eq!(stream.unwrap().1.len(), 2);

    Ok(())
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
    use std::{sync::Arc, fs};
    use crate::database::sled::SledEventDatabase;
    let body = br#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let stream = signed_event_stream(body);
    assert_eq!(stream.unwrap().1.len(), 2);

    use tempfile::Builder;

    // Create test db and event processor.
    let root = Builder::new().prefix("test-db").tempdir().unwrap();
    fs::create_dir_all(root.path()).unwrap();

    let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    let validator = EventValidator::new(Arc::clone(&db));

    let mut oobi_manager = OobiManager::new(validator);
    oobi_manager.process_oobi("http://127.0.0.1:5643/oobi/BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw/controller")?;
    oobi_manager.load().await?;

    Ok(())
}
