use std::path::Path;

use actix_web::{dev::Server, web, App, HttpServer};
use futures::future::join_all;
use keri::{error::Error, oobi::LocationScheme, prefix::BasicPrefix};

use crate::watcher::{Watcher, WatcherData};

pub struct WatcherListener {
    watcher_data: Watcher,
}

impl WatcherListener {
    pub fn setup(
        address: url::Url,
        public_address: Option<String>,
        event_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let pub_address = if let Some(pub_address) = public_address {
            url::Url::parse(&format!("http://{}", pub_address)).unwrap()
        } else {
            address.clone()
        };

        WatcherData::setup(pub_address, event_db_path, priv_key).map(|watcher_data| Self {
            watcher_data: Watcher(watcher_data),
        })
    }

    pub fn listen_http(self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(self.watcher_data);
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(http_handlers::get_eid_oobi)
                .service(http_handlers::get_cid_oobi)
                .service(http_handlers::get_kel)
                .service(http_handlers::resolve_oobi)
                .service(http_handlers::process_notice)
                .service(http_handlers::process_op)
            // .service(resolve)
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub async fn resolve_initial_oobis(
        &self,
        initial_oobis: &[LocationScheme],
    ) -> Result<(), Error> {
        join_all(
            initial_oobis
                .iter()
                .map(|lc| self.watcher_data.resolve_loc_scheme(lc)),
        )
        .await;
        Ok(())
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.watcher_data.0.prefix.clone()
    }
}

pub mod http_handlers {

    use actix_web::{
        get, http::header::ContentType, post, web, HttpResponse, Responder, ResponseError,
    };
    use derive_more::{Display, Error, From};
    use itertools::Itertools;
    use keri::{
        derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
        error::Error,
        event_message::signed_event_message::{Message, Op},
        event_parsing::SignedEventData,
        oobi::{error::OobiError, EndRole, LocationScheme, Role},
        prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix},
        query::query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
    };
    use reqwest::StatusCode;
    use serde::Deserialize;

    use crate::watcher::{Watcher, WatcherData, WatcherError};

    #[post("/process")]
    async fn process_notice(
        body: web::Bytes,
        data: web::Data<Watcher>,
    ) -> Result<impl Responder, ApiError> {
        println!(
            "\nGot events to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        data.0.parse_and_process_notices(&body)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    #[post("/query")]
    async fn process_op(
        body: web::Bytes,
        data: web::Data<Watcher>,
    ) -> Result<impl Responder, ApiError> {
        println!(
            "\nGot events to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        let resp = data
            .0
            .parse_and_process_ops(&body)?
            .iter()
            .map(|msg| msg.to_cesr())
            .flatten_ok()
            .try_collect()?;

        // TODO: check if query cid in oobi_manager - end_role watcher

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(resp).unwrap()))
    }

    // TODO: merge with above method
    #[get("/query/{id}")]
    async fn get_kel(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Watcher>,
    ) -> Result<impl Responder, ApiError> {
        // generate query message here
        let id = eid.clone();
        let qr = QueryArgs {
            s: None,
            i: id.clone(),
            src: None,
        };
        let qry_message = QueryEvent::new_query(
            QueryRoute::Log {
                args: qr,
                reply_route: String::from(""),
            },
            keri::event::SerializationFormats::JSON,
            &SelfAddressing::Blake3_256,
        )?;
        let signature = data.0.signer.sign(qry_message.serialize()?)?;
        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_qry = SignedQuery::new(
            qry_message,
            keri::prefix::IdentifierPrefix::Basic(data.0.prefix.clone()),
            signatures,
        );

        // Get witnesses, and TODO choose one randomly.
        let witnesses = data
            .0
            .get_state_for_prefix(&id)?
            .ok_or_else(|| ApiError::NoStateForPrefix { prefix: id })?
            .witness_config
            .witnesses;
        let witness_id = IdentifierPrefix::Basic(witnesses[0].clone());

        // get witness address and send there query
        let qry_str = Message::Op(Op::Query(signed_qry)).to_cesr()?;
        println!(
            "\nSending query to {}: \n{}",
            witness_id.to_str(),
            String::from_utf8_lossy(&qry_str)
        );
        let resp = data
            .send_to(witness_id.clone(), keri::oobi::Scheme::Http, qry_str)
            .await?
            .ok_or_else(|| ApiError::NoResponse { witness_id })?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    #[post("/resolve")]
    async fn resolve_oobi(
        body: web::Bytes,
        data: web::Data<Watcher>,
    ) -> Result<impl Responder, ApiError> {
        println!(
            "\nGot oobi to resolve: \n{}",
            String::from_utf8_lossy(&body)
        );

        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum RequestData {
            EndRole(EndRole),
            LocationScheme(LocationScheme),
        }

        match serde_json::from_slice(&body)? {
            RequestData::EndRole(end_role) => {
                data.resolve_end_role(end_role).await?;
            }
            RequestData::LocationScheme(loc_scheme) => {
                data.resolve_loc_scheme(&loc_scheme).await?;
            }
        }

        Ok(HttpResponse::Ok())
    }

    #[get("/oobi/{id}")]
    async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<WatcherData>,
    ) -> Result<impl Responder, ApiError> {
        let loc_scheme = data.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten()
            .collect();

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    #[get("/oobi/{cid}/{role}/{eid}")]
    async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<WatcherData>,
    ) -> Result<impl Responder, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data.oobi_manager.get_end_role(&cid, role)?;
        let loc_scheme = data.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten()
            .collect();
        println!(
            "\nSending {} obi from its watcher {}:\n{}",
            cid.to_str(),
            eid.to_str(),
            String::from_utf8_lossy(&oobis)
        );

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    #[derive(Debug, Display, Error, From)]
    pub enum ApiError {
        #[display(fmt = "DB error")]
        #[from]
        DbError(keri::database::sled::DbError),

        #[display(fmt = "deserialize error")]
        #[from]
        DeserializeError(serde_json::Error),

        #[display(fmt = "keri error")]
        #[from]
        KeriError(Error),

        #[display(fmt = "watcher error")]
        #[from]
        WatcherError(WatcherError),

        #[display(fmt = "no state for prefix {}", prefix)]
        NoStateForPrefix { prefix: IdentifierPrefix },

        #[display(fmt = "no response from witness {}", witness_id)]
        NoResponse { witness_id: IdentifierPrefix },
    }

    impl ResponseError for ApiError {
        fn status_code(&self) -> StatusCode {
            match self {
                ApiError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,

                ApiError::DeserializeError(_) => StatusCode::BAD_REQUEST,

                ApiError::KeriError(err) => match err {
                    Error::Base64DecodingError { .. }
                    | Error::DeserializeError(_)
                    | Error::IncorrectDigest => StatusCode::BAD_REQUEST,

                    Error::Ed25519DalekSignatureError(_)
                    | Error::FaultySignatureVerification
                    | Error::SignatureVerificationError => StatusCode::FORBIDDEN,

                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },

                ApiError::WatcherError(err) => match err {
                    WatcherError::OobiError(err) => match err {
                        OobiError::SignerMismatch => StatusCode::FORBIDDEN,

                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    },

                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },

                ApiError::NoStateForPrefix { .. } => StatusCode::BAD_GATEWAY,

                ApiError::NoResponse { .. } => StatusCode::BAD_GATEWAY,
            }
        }
    }
}
