use std::convert::TryFrom;

use cesrox::parse_many;

use crate::{
    error::Error,
    event_message::signed_event_message::{Message, Op},
    oobi::{error::OobiError, Role},
    prefix::IdentifierPrefix,
    query::reply_event::{bada_logic, ReplyEvent, ReplyRoute, SignedReply},
};

pub mod storage;

use self::storage::OobiStorageBackend;

#[cfg(feature = "storage-redb")]
use self::storage::RedbOobiStorage;

#[cfg(feature = "storage-redb")]
pub struct OobiManager<S: OobiStorageBackend = RedbOobiStorage> {
    store: S,
}

#[cfg(not(feature = "storage-redb"))]
pub struct OobiManager<S: OobiStorageBackend> {
    store: S,
}

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
                if let Some(old_rpy) = self
                    .store
                    .get_end_role(&er.cid, er.role)
                    .map_err(|e| OobiError::Db(e.to_string()))?
                    .and_then(|rpys| rpys.last().cloned())
                {
                    bada_logic(rpy, &old_rpy)?;
                };
                Ok(())
            }
            _ => Err(OobiError::InvalidMessageType),
        }
    }

    pub fn parse_and_save(&self, stream: &str) -> Result<(), OobiError> {
        parse_many(stream.as_bytes())
            .map_err(|_| OobiError::Parse(stream.to_string()))?
            .1
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

    pub fn get_loc_scheme(&self, id: &IdentifierPrefix) -> Result<Vec<ReplyEvent>, OobiError> {
        Ok(self
            .store
            .get_oobis_for_eid(id)
            .map_err(|e| OobiError::Db(e.to_string()))?
            .into_iter()
            .map(|e| e.reply)
            .collect())
    }

    pub fn get_end_role(
        &self,
        id: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, OobiError> {
        self.store
            .get_end_role(id, role)
            .map_err(|e| OobiError::Db(e.to_string()))
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

#[cfg(feature = "storage-redb")]
impl OobiManager<RedbOobiStorage> {
    /// Create a redb-backed OobiManager from a `RedbDatabase` wrapper.
    pub fn new(events_db: std::sync::Arc<crate::database::redb::RedbDatabase>) -> Result<Self, OobiError> {
        let store = RedbOobiStorage::new(events_db.db.clone())
            .map_err(|e| OobiError::Db(e.to_string()))?;
        Ok(Self { store })
    }

    /// Create a redb-backed OobiManager directly from a raw redb `Database`.
    pub fn new_redb(db: std::sync::Arc<redb::Database>) -> Result<Self, OobiError> {
        let store = RedbOobiStorage::new(db).map_err(|e| OobiError::Db(e.to_string()))?;
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

    use cesrox::parse_many;
    use tempfile::NamedTempFile;

    use crate::{
        oobi::error::OobiError,
        oobi_manager::OobiManager,
        prefix::IdentifierPrefix,
        query::reply_event::ReplyRoute,
    };

    fn setup_oobi_manager() -> OobiManager {
        let tmp_path = NamedTempFile::new().unwrap();
        let redb = Arc::new(redb::Database::create(tmp_path.path()).unwrap());
        OobiManager::new_redb(redb).unwrap()
    }

    #[test]
    fn test_obi_save() -> Result<(), OobiError> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EJq4dQQdqg8aK7VyGnfSibxPyW8Zk2zO1qbVRD6flOvE","dt":"2022-02-28T17:23:20.336207+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BAPJ5p_IpUFdmq8uupehsL8DzxWDeaU_SjeiwfmRZ6i9pqddraItmCOAysdXdTEQZ1hEM60iDEWvK16g68TrcAw{"v":"KERI10JSON0000f8_","t":"rpy","d":"ExSR01j5noF2LnGcGFUbLnq-U8JuYBr9WWEMt8d2fb1Y","dt":"2022-02-28T17:23:20.337272+00:00","r":"/loc/scheme","a":{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}}-VAi-CABBuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw0BZtIhK6Nh6Zk1zPmkJYiFVz0RimQRiubshmSmqAzxzhT4KpGMAH7sbNlFP-0-lKjTawTReKv4L7N3TR7jxXaEBg"#;
        let stream = parse_many(body.as_bytes());
        assert_eq!(stream.unwrap().1.len(), 2);

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.get_loc_scheme(
            &"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw"
                .parse::<IdentifierPrefix>()
                .unwrap(),
        )?;
        assert!(!res.is_empty());

        assert_eq!(
            res.iter().map(|oobi| oobi.get_route()).collect::<Vec<_>>(),
            vec![
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"http","url":"http://127.0.0.1:5643/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"BuyRFMideczFZoapylLIyCjSdhtqVb31wZkRKvPfNqkw","scheme":"tcp","url":"tcp://127.0.0.1:5633/"}"#).unwrap()),
            ]
        );

        Ok(())
    }

    #[test]
    pub fn test_oobi_update() -> Result<(), OobiError> {
        let oobi_manager = setup_oobi_manager();

        let body = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"Elxbk-5h8a2PhoserezofHRXEDgAEwhrW0wvhXqyupmY","dt":"2022-04-08T15:00:29.163849+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BezpFQMVxodb7WMUBL4aLeQW1CUTUYbcFNPGohh02cKl7kSajyRZAentI-MkconvyI8-QfaO1in5mexYF-1ZPBg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EfJP2Mkp_2UZJoWoNCWZHMgU7uWMIkzih19Nvit36Cho","dt":"2022-04-08T15:00:29.165103+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BFcwrcL7Hc8HYLSPvzMGAAEn5QyY76QWY1l2RotQqsX01HgDh4UZYU5GpiVY2A-AbsRIsUpfIKnQi7r4dc0o0DA"#;
        let body2 = r#"{"v":"KERI10JSON0000fa_","t":"rpy","d":"EhmRb98IbAp7xqttLe-knTcT0pg5xbkFdU-D8FMi2NTE","dt":"2022-04-08T15:02:55.382713+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BQ2LHGCoTDzGTU4qnAKvnZocjUEwWfpILfngi5Ej3z_7SGJ5q4ciQSZ2uyBONGNqDeOsyrI4vV5LvrQUxg0vLCg{"v":"KERI10JSON0000f8_","t":"rpy","d":"EQqXdsemACUttgKUOiCYTs9JyXIjbio1itQdA2TeKF0I","dt":"2022-04-08T15:02:55.384117+00:00","r":"/loc/scheme","a":{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}}-VAi-CABBgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c0BD1uIyxgm1MFqhkwlbwarxOdNghWIrs_ClHLrHVj-qpGpS2cM1T1Y8E3GUsfvpsvkHNWUFCBZmaQHoSI4WE2cAw"#;

        oobi_manager.parse_and_save(body)?;

        let res = oobi_manager.get_loc_scheme(
            &"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
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
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
            ]
        );

        oobi_manager.parse_and_save(body2)?;

        let res = oobi_manager.get_loc_scheme(
            &"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c"
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
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"http","url":"http://127.0.0.1:5644/"}"#).unwrap()),
                ReplyRoute::LocScheme(serde_json::from_str(r#"{"eid":"Bgoq68HCmYNUDgOz4Skvlu306o_NY-NrYuKAVhk3Zh9c","scheme":"tcp","url":"tcp://127.0.0.1:5634/"}"#).unwrap())
            ]
        );
        assert_ne!(timestamps, timestamps2);

        Ok(())
    }
}
