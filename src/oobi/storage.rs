use std::path::Path;

use reqwest::Url;
use sled::Db;

use crate::database::sled::tables::{SledEventTree, SledEventTreeVec};
use crate::event_parsing::message::signed_event_stream;
use crate::oobi::OobiManager;
use crate::processor::validator::EventValidator;
use crate::query::reply_event::ReplyRoute;
use crate::{prefix::IdentifierPrefix, query::reply_event::SignedReply};

use super::EndRole;
use super::{error::Error, LocationScheme};

pub struct OobiStorage {
    identifiers: SledEventTree<IdentifierPrefix>,
    // subdatabase for endpoint providers oobis
    oobis: SledEventTreeVec<SignedReply>,
    // subdatabase for identifiers with use eids as their witnesses,watchers etc.
    // it will be used to store `end/role` messages with will provide proof,
    // that identifier choose those eids to play a role for them
    cids: SledEventTreeVec<EndRole>,
}

impl OobiStorage {
    pub fn new(db_path: &Path) -> Result<Self, Error> {
        let db: Db = sled::open(db_path)?;
        Ok(OobiStorage {
            identifiers: SledEventTree::new(db.open_tree(b"iids")?),
            oobis: SledEventTreeVec::new(db.open_tree(b"oobis")?),
            cids: SledEventTreeVec::new(db.open_tree(b"cids")?),
        })
    }

    pub fn get_oobis_for_eid(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        let key = self.identifiers.designated_key(id);
        Ok(self.oobis.get(key)?)
    }

    pub fn get_last_loc_scheme(
        &self,
        loc_scheme: LocationScheme,
    ) -> Result<Option<SignedReply>, Error> {
        let rpy = self
            .get_oobis_for_eid(&loc_scheme.eid)?
            .unwrap()
            .into_iter()
            .find(|rpy| {
                if let ReplyRoute::LocScheme(lc) = rpy.reply.get_route() {
                    lc.scheme == loc_scheme.scheme
                } else {
                    false
                }
            });
        Ok(rpy)
    }

    pub fn get_eid_for_cid(
        &self,
        cid: &IdentifierPrefix,
        role: &str,
    ) -> Result<Vec<IdentifierPrefix>, Error> {
        let key = self.identifiers.designated_key(cid);
        Ok(self
            .cids
            .get(key)?
            .unwrap()
            .into_iter()
            .filter(|oobi| oobi.role == role.to_string())
            .map(|oobi| oobi.eid)
            .collect())
    }

    pub fn get_urls(&self, id: &IdentifierPrefix) -> Result<Option<Vec<url::Url>>, Error> {
        let oobi_rpy = self.get_oobis_for_eid(id);
        oobi_rpy.map(|some_reply| {
            some_reply.map(|oobi_rpy_list| {
                oobi_rpy_list
                    .into_iter()
                    .map(|oobi_rpy| {
                        if let ReplyRoute::LocScheme(loc_scheme) = oobi_rpy.reply.get_route() {
                            loc_scheme.url
                        } else {
                            todo!()
                        }
                    })
                    .collect()
            })
        })
    }

    pub fn save_oobi(&self, oobi_reply: SignedReply) -> Result<(), Error> {
        match oobi_reply.reply.get_route() {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(loc_scheme) => {
                let key = self.identifiers.designated_key(&loc_scheme.eid);
                let oobi = oobi_reply.reply.event.content.clone();

                // update last saved reply for given schema with the new one
                match self.oobis.iter_values(key) {
                    Some(values) => {
                        let value = values
                            .filter(|oobi_rpy| oobi_rpy.reply.event.content != oobi)
                            .chain(vec![oobi_reply])
                            .collect::<Vec<_>>();
                        self.oobis.put(key, value)
                    }
                    None => self.oobis.push(key, oobi_reply),
                }?;
            }
            ReplyRoute::EndRole(end_role) => {
                let key = self.identifiers.designated_key(&end_role.cid);
                // TODO this also will be signed reply
                self.cids.push(key, end_role)?
            }
        };
        Ok(())
    }
}

#[test]
fn test_obi_save() -> Result<(), Error> {
    use crate::database::sled::SledEventDatabase;
    use std::{fs, sync::Arc};
    // let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg"#;
    // let stream = signed_event_stream(endrole.as_bytes());
    let endrole = r#"{"v":"KERI10JSON000116_","t":"rpy","d":"EcZ1I4nKy6gIkWxjq1LmIivoPGv32lvlSuMVsWnOPwSc","dt":"2022-02-28T17:23:20.338355+00:00","r":"/end/role/add","a":{"cid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","role":"controller","eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0B9ccIiMxdwurRjGvUUUdXsxhseo58onhE4bJddKuyPaSpBHXdRKKuiFE0SmLAogMQGJ0iN6f1V_2E_MVfMc3sAA"#;
    let stream = crate::event_parsing::message::signed_message(endrole.as_bytes());
    println!("{:?}", stream);
    // assert_eq!(stream.unwrap().1.len(), 1);
    use tempfile::Builder;

    // // Create test db and event processor.
    // let root = Builder::new().prefix("test-db").tempdir().unwrap();
    // fs::create_dir_all(root.path()).unwrap();
    // let oobi_root = Builder::new().prefix("oobi-test-db").tempdir().unwrap();
    // fs::create_dir_all(oobi_root.path()).unwrap();

    // let db = Arc::new(SledEventDatabase::new(root.path()).unwrap());
    // let validator = EventValidator::new(Arc::clone(&db));

    // let oobi_manager = OobiManager::new(validator, oobi_root.path());

    // // let wrong_body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAA"#;

    // oobi_manager.parse_and_save(body)?;

    // let res = oobi_manager.store.get_urls(
    //     &"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"
    //         .parse::<IdentifierPrefix>()
    //         .unwrap(),
    // )?;
    // assert_eq!(
    //     res,
    //     Some(vec![
    //         Url::parse("http://127.0.0.1:5643/").unwrap(),
    //         Url::parse("tcp://127.0.0.1:5633/").unwrap()
    //     ])
    // );

    Ok(())
}
