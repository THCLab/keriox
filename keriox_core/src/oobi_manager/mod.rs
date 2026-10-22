use std::convert::TryFrom;

use crate::event_message::cesr_adapter::parse_cesr_stream_many;

use crate::{
    error::Error,
    event_message::signed_event_message::{Message, Op},
    oobi::{error::OobiError, Role, Scheme},
    prefix::IdentifierPrefix,
    query::reply_event::{bada_logic, ReplyEvent, ReplyRoute, SignedReply},
};

pub mod storage;

pub use self::storage::OobiStorageBackend;
#[cfg(feature = "storage-redb")]
pub use self::storage::RedbOobiStorage;
#[cfg(feature = "storage-postgres")]
pub use crate::database::postgres::oobi_storage::PostgresOobiStorage;

pub struct OobiManager<S: OobiStorageBackend> {
    store: S,
}

#[cfg(feature = "storage-redb")]
pub type RedbOobiManager = OobiManager<self::storage::RedbOobiStorage>;

#[cfg(feature = "storage-postgres")]
pub type PostgresOobiManager =
    OobiManager<crate::database::postgres::oobi_storage::PostgresOobiStorage>;

impl<S: OobiStorageBackend> OobiManager<S> {
    pub fn with_storage(store: S) -> Self {
        Self { store }
    }

    /// Checks oobi signer and bada logic. Assumes signatures already verified.
    pub fn check_oobi_reply(&self, rpy: &SignedReply) -> Result<(), OobiError> {
        match rpy.reply.get_route() {
            ReplyRoute::LocScheme(lc) => {
                if rpy.signature.get_signer().ok_or(Error::MissingSigner)? != lc.get_eid() {
                    return Err(OobiError::SignerMismatch);
                };

                if let Some(old_rpy) = self
                    .store
                    .get_last_loc_scheme(&lc.eid, &lc.scheme)
                    .map_err(|e| OobiError::Db(e.to_string()))?
                {
                    bada_logic(rpy, &old_rpy)?;
                };
                Ok(())
            }
            ReplyRoute::EndRoleAdd(er) | ReplyRoute::EndRoleCut(er) => {
                if rpy.signature.get_signer().ok_or(Error::MissingSigner)? != er.cid {
                    return Err(OobiError::SignerMismatch);
                };
                // Each endpoint's authorization is its own record, so the
                // update is checked against that endpoint's latest reply.
                if let Some(old_rpy) = self
                    .end_role_records(&er.cid, er.role)?
                    .into_iter()
                    .find(|old| end_role_eid(old).as_ref() == Some(&er.eid))
                {
                    bada_logic(rpy, &old_rpy)?;
                };
                Ok(())
            }
            _ => Err(OobiError::InvalidMessageType),
        }
    }

    pub fn parse_and_save(&self, stream: &str) -> Result<(), OobiError> {
        let messages = parse_cesr_stream_many(stream.as_bytes())
            .map_err(|_| OobiError::Parse(stream.to_string()))?;
        messages
            .into_iter()
            .try_for_each(|sed| -> Result<_, OobiError> {
                let msg = Message::try_from(sed).unwrap();
                match msg {
                    Message::Op(Op::Reply(oobi_rpy)) => {
                        self.check_oobi_reply(&oobi_rpy)?;
                        self.store
                            .save_oobi(&oobi_rpy)
                            .map_err(|e| OobiError::Db(e.to_string()))?;
                        Ok(())
                    }
                    _ => Err(OobiError::InvalidMessageType),
                }
            })?;
        Ok(())
    }

    pub fn save_oobi(&self, signed_oobi: &SignedReply) -> Result<(), OobiError> {
        self.store
            .save_oobi(signed_oobi)
            .map_err(|e| OobiError::Db(e.to_string()))
    }

    /// The locations `id` currently has: the latest reply for each scheme,
    /// unless that reply nullified the location with an empty url.
    pub fn get_loc_scheme(&self, id: &IdentifierPrefix) -> Result<Vec<ReplyEvent>, OobiError> {
        Ok(self
            .store
            .get_oobis_for_eid(id)
            .map_err(|e| OobiError::Db(e.to_string()))?
            .into_iter()
            .map(|e| e.reply)
            .filter(|reply| {
                !matches!(reply.get_route(), ReplyRoute::LocScheme(loc) if loc.url.is_none())
            })
            .collect())
    }

    /// The endpoints `id` currently authorizes in `role`: the latest reply
    /// for each endpoint, when that reply is an `/end/role/add`. A cut
    /// nullifies the endpoint's record, so it is not returned.
    pub fn get_end_role(
        &self,
        id: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, OobiError> {
        let active: Vec<SignedReply> = self
            .end_role_records(id, role)?
            .into_iter()
            .filter(|rpy| matches!(rpy.reply.get_route(), ReplyRoute::EndRoleAdd(_)))
            .collect();
        Ok((!active.is_empty()).then_some(active))
    }

    /// The record of the location of `eid` for `scheme`: its latest reply,
    /// which may have nullified the location.
    pub fn loc_scheme_record(
        &self,
        eid: &IdentifierPrefix,
        scheme: &Scheme,
    ) -> Result<Option<SignedReply>, OobiError> {
        self.store
            .get_last_loc_scheme(eid, scheme)
            .map_err(|e| OobiError::Db(e.to_string()))
    }

    /// The record of each endpoint of `id` in `role`: its latest reply, an
    /// add (authorized) or a cut (nullified). Storage keeps one per endpoint;
    /// stores written before that kept every reply, so the latest by
    /// date-time wins.
    pub fn end_role_records(
        &self,
        id: &IdentifierPrefix,
        role: Role,
    ) -> Result<Vec<SignedReply>, OobiError> {
        let mut latest: Vec<SignedReply> = vec![];
        for rpy in self
            .store
            .get_end_role(id, role)
            .map_err(|e| OobiError::Db(e.to_string()))?
            .unwrap_or_default()
        {
            let eid = end_role_eid(&rpy);
            match latest.iter_mut().find(|kept| end_role_eid(kept) == eid) {
                Some(kept) if rpy.reply.get_timestamp() > kept.reply.get_timestamp() => *kept = rpy,
                Some(_) => {}
                None => latest.push(rpy),
            }
        }
        Ok(latest)
    }

    /// Assumes that signatures were verified.
    pub fn process_oobi(&self, oobi_rpy: &SignedReply) -> Result<(), OobiError> {
        self.check_oobi_reply(oobi_rpy)?;
        self.store
            .save_oobi(oobi_rpy)
            .map_err(|e| OobiError::Db(e.to_string()))?;
        Ok(())
    }
}

/// The endpoint an end role reply is about.
fn end_role_eid(rpy: &SignedReply) -> Option<IdentifierPrefix> {
    match rpy.reply.get_route() {
        ReplyRoute::EndRoleAdd(er) | ReplyRoute::EndRoleCut(er) => Some(er.eid),
        _ => None,
    }
}

#[cfg(feature = "storage-redb")]
impl OobiManager<self::storage::RedbOobiStorage> {
    /// Create a redb-backed OobiManager from a `RedbDatabase` wrapper.
    pub fn new(
        events_db: std::sync::Arc<crate::database::redb::RedbDatabase>,
    ) -> Result<Self, OobiError> {
        let store = self::storage::RedbOobiStorage::new(events_db.db.clone())
            .map_err(|e| OobiError::Db(e.to_string()))?;
        Ok(Self { store })
    }

    /// Create a redb-backed OobiManager directly from a raw redb `Database`.
    pub fn new_redb(db: std::sync::Arc<redb::Database>) -> Result<Self, OobiError> {
        let store =
            self::storage::RedbOobiStorage::new(db).map_err(|e| OobiError::Db(e.to_string()))?;
        Ok(Self { store })
    }
}

#[cfg(feature = "storage-postgres")]
impl OobiManager<crate::database::postgres::oobi_storage::PostgresOobiStorage> {
    /// Create a postgres-backed OobiManager from an existing `PgPool`.
    pub fn new_postgres(pool: sqlx::PgPool) -> Self {
        Self {
            store: crate::database::postgres::oobi_storage::PostgresOobiStorage::new(pool),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::event_message::cesr_adapter::parse_cesr_stream_many;
    use tempfile::NamedTempFile;

    use crate::{
        oobi::error::OobiError,
        oobi_manager::{OobiManager, RedbOobiManager},
        prefix::IdentifierPrefix,
        query::reply_event::ReplyRoute,
    };

    fn setup_oobi_manager() -> RedbOobiManager {
        let tmp_path = NamedTempFile::new().unwrap();
        let redb = Arc::new(redb::Database::create(tmp_path.path()).unwrap());
        OobiManager::new_redb(redb).unwrap()
    }

    #[test]
    fn test_obi_save() -> Result<(), OobiError> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-MABBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"EBSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-MABBOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BBtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg"#;
        let messages = parse_cesr_stream_many(body.as_bytes());
        assert_eq!(messages.unwrap().len(), 2);

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.get_loc_scheme(
            &"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(!res.is_empty());

        assert_eq!(
            res.iter().map(|oobi| oobi.get_route()).collect::<Vec<_>>(),
            vec![
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BOyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}"#).unwrap()),
            ]
        );

        Ok(())
    }

    #[test]
    pub fn test_oobi_update() -> Result<(), OobiError> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EFxbk-5h8a2PhoserezofHRXEDgAEwhrW0wvhXqyupmY","dt":"2022-04-08T15:00:29.163849+00:00","r":"/loc/scheme","a":{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-MABBAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BCzpFQMVxodb7WMUBL4aLeQW1CUTUYbcFNPGohh02cKl7kSajyRZAentI-MkconvyI8-QfaO1in5mexYF-1ZPBg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EPJP2Mkp_2UZJoWoNCWZHMgU7uWMIkzih19Nvit36Cho","dt":"2022-04-08T15:00:29.165103+00:00","r":"/loc/scheme","a":{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-MABBAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BBcwrcL7Hc8HYLSPvzMGAAEn5QyY76QWY1l2RotQqsX01HgDh4UZYU5GpiVY2A-AbsRIsUpfIKnQi7r4dc0o0DA"#;
        let body2 = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EBmRb98IbAp7xqttLe-knTcT0pg5xbkFdU-D8FMi2NTE","dt":"2022-04-08T15:02:55.382713+00:00","r":"/loc/scheme","a":{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-MABBAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BA2LHGCoTDzGTU4qnAKvnZocjUEwWfpILfngi5Ej3z_7SGJ5q4ciQSZ2uyBONGNqDeOsyrI4vV5LvrQUxg0vLCg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EAqXdsemACUttgKUOiCYTs9JyXIjbio1itQdA2TeKF0I","dt":"2022-04-08T15:02:55.384117+00:00","r":"/loc/scheme","a":{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-MABBAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BD1uIyxgm1MFqhkwlbwarxOdNghWIrs_ClHLrHVj-qpGpS2cM1T1Y8E3GUsfvpsvkHNWUFCBZmaQHoSI4WE2cAw"#;

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.get_loc_scheme(
            &"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(!res.is_empty());
        let timestamps = res
            .iter()
            .map(|reply| reply.get_timestamp())
            .collect::<Vec<_>>();

        assert_eq!(
            res.iter().map(|oobi| oobi.get_route()).collect::<Vec<_>>(),
            vec![
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
            ]
        );

        oobi_manager.parse_and_save(body2)?;

        let res = oobi_manager.get_loc_scheme(
            &"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(!res.is_empty());
        let timestamps2 = res
            .iter()
            .map(|reply| reply.get_timestamp())
            .collect::<Vec<_>>();

        assert_eq!(
            res.iter().map(|oobi| oobi.get_route()).collect::<Vec<_>>(),
            vec![
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BAoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
            ]
        );
        assert_ne!(timestamps, timestamps2);

        Ok(())
    }

    /// Replies authorizing (or cutting) `eid` in `role` for `cid`, signed by
    /// `cid`. Each call has a later `dt` than the previous one.
    mod end_roles {
        use said::{derivation::HashFunctionCode, version::format::SerializationFormats};

        use crate::{
            oobi::{EndRole, Role},
            prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
            query::{
                reply_event::{ReplyEvent, ReplyRoute, SignedReply},
                QueryError,
            },
            signer::Signer,
        };

        use super::setup_oobi_manager;
        use crate::oobi::error::OobiError;

        struct Controller {
            key: BasicPrefix,
        }

        impl Controller {
            fn new() -> Self {
                Self {
                    key: BasicPrefix::Ed25519NT(Signer::new().public_key()),
                }
            }

            fn cid(&self) -> IdentifierPrefix {
                IdentifierPrefix::Basic(self.key.clone())
            }

            fn reply(&self, add: bool, eid: &IdentifierPrefix) -> SignedReply {
                let end_role = EndRole {
                    cid: self.cid(),
                    role: Role::Watcher,
                    eid: eid.clone(),
                };
                let route = if add {
                    ReplyRoute::EndRoleAdd(end_role)
                } else {
                    ReplyRoute::EndRoleCut(end_role)
                };
                let rpy = ReplyEvent::new_reply(
                    route,
                    HashFunctionCode::Blake3_256,
                    SerializationFormats::JSON,
                );
                // Stored replies are checked for their signer and order
                // only; signatures are verified before they get here.
                SignedReply::new_nontrans(
                    rpy,
                    self.key.clone(),
                    SelfSigningPrefix::Ed25519Sha512(vec![0; 64]),
                )
            }
        }

        fn eid() -> IdentifierPrefix {
            IdentifierPrefix::Basic(BasicPrefix::Ed25519NT(Signer::new().public_key()))
        }

        fn watchers(
            manager: &crate::oobi_manager::RedbOobiManager,
            cid: &IdentifierPrefix,
        ) -> Vec<IdentifierPrefix> {
            manager
                .get_end_role(cid, Role::Watcher)
                .unwrap()
                .unwrap_or_default()
                .into_iter()
                .map(|rpy| match rpy.reply.get_route() {
                    ReplyRoute::EndRoleAdd(er) => er.eid,
                    other => panic!("an inactive role was returned: {other:?}"),
                })
                .collect()
        }

        #[test]
        fn a_cut_nullifies_the_authorization() -> Result<(), OobiError> {
            let manager = setup_oobi_manager();
            let (controller, watcher) = (Controller::new(), eid());
            let add = controller.reply(true, &watcher);
            let cut = controller.reply(false, &watcher);

            manager.process_oobi(&add)?;
            assert_eq!(watchers(&manager, &controller.cid()), vec![watcher.clone()]);

            manager.process_oobi(&cut)?;
            assert!(watchers(&manager, &controller.cid()).is_empty());

            // The older authorization, replayed, is stale.
            assert!(matches!(
                manager.process_oobi(&add),
                Err(OobiError::Query(QueryError::StaleRpy))
            ));
            assert!(watchers(&manager, &controller.cid()).is_empty());

            // A newer one authorizes it again.
            manager.process_oobi(&controller.reply(true, &watcher))?;
            assert_eq!(watchers(&manager, &controller.cid()), vec![watcher]);
            Ok(())
        }

        #[test]
        fn each_endpoint_is_its_own_record() -> Result<(), OobiError> {
            let manager = setup_oobi_manager();
            let (controller, first, second) = (Controller::new(), eid(), eid());
            // Built first, so older than the authorization of `first`.
            let older_for_second = controller.reply(true, &second);
            manager.process_oobi(&controller.reply(true, &first))?;

            // Not stale: no earlier record for `second` exists.
            manager.process_oobi(&older_for_second)?;
            let mut listed = watchers(&manager, &controller.cid());
            listed.sort_by_key(|id| id.to_string());
            let mut expected = vec![first.clone(), second.clone()];
            expected.sort_by_key(|id| id.to_string());
            assert_eq!(listed, expected);

            // Cutting one leaves the other.
            manager.process_oobi(&controller.reply(false, &first))?;
            assert_eq!(watchers(&manager, &controller.cid()), vec![second]);
            Ok(())
        }
    }
}
