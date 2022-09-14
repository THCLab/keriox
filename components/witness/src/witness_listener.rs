use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::{dev::Server, web::Data, App, HttpServer};
use anyhow::Result;
use keri::{self, error::Error, prefix::BasicPrefix};

use crate::witness::Witness;

pub struct WitnessListener {
    witness_data: Arc<Witness>,
}

impl WitnessListener {
    pub fn setup(
        address: url::Url,
        public_address: Option<String>,
        event_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let mut oobi_path = PathBuf::new();
        oobi_path.push(event_db_path);
        oobi_path.push("oobi");

        let pub_address = if let Some(pub_address) = public_address {
            url::Url::parse(&format!("http://{}", pub_address)).unwrap()
        } else {
            address.clone()
        };

        Witness::setup(pub_address, event_db_path, oobi_path.as_path(), priv_key).map(|wd| Self {
            witness_data: Arc::new(wd),
        })
    }

    pub fn listen_http(&self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = Data::new(self.witness_data.clone());
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(http_handlers::get_eid_oobi)
                .service(http_handlers::get_cid_oobi)
                .service(http_handlers::process_notice)
                .service(http_handlers::process_query)
                .service(http_handlers::process_reply)
                .service(http_handlers::process_exchange)
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.witness_data.prefix.clone()
    }
}

pub mod http_handlers {
    use std::sync::Arc;

    use actix_web::{
        get,
        http::{header::ContentType, StatusCode},
        post, web, HttpResponse, Responder, ResponseError,
    };
    use derive_more::{Display, Error, From};
    use itertools::Itertools;
    use keri::{
        actor::{QueryError, SignedQueryError},
        error::Error,
        event_parsing::SignedEventData,
        oobi::Role,
        prefix::{IdentifierPrefix, Prefix},
    };

    use crate::witness::{Witness, WitnessError};

    #[get("/oobi/{id}")]
    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<impl Responder, ApiError> {
        let loc_scheme = data.get_loc_scheme_for_id(&eid)?.unwrap_or(vec![]);
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr()
            })
            .flatten_ok()
            .try_collect()?;

        println!(
            "\nSending {} oobi: \n {}",
            &eid.to_str(),
            String::from_utf8(oobis.clone()).unwrap_or_default()
        );
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    #[get("/oobi/{cid}/{role}/{eid}")]
    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<impl Responder, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data.oobi_manager.get_end_role(&cid, role)?;
        let loc_scheme = data.get_loc_scheme_for_id(&eid)?.unwrap_or(vec![]);
        // (for now) Append controller kel to be able to verify end role signature.
        // TODO use ksn instead
        let cont_kel = data.event_storage.get_kel(&cid)?.unwrap_or_default();
        let oobis = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr()
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, _>>()?;
        let res: Vec<u8> = cont_kel.into_iter().chain(oobis).collect();
        println!(
            "\nSending {} obi from its witness {}:\n{}",
            cid.to_str(),
            eid.to_str(),
            String::from_utf8_lossy(&res)
        );

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(res).unwrap()))
    }

    #[post("/process")]
    pub async fn process_notice(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<impl Responder, ApiError> {
        println!("\nGot notice to process: \n{}", post_data);
        data.parse_and_process_notices(post_data.as_bytes())?;
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    #[post("/query")]
    pub async fn process_query(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<impl Responder, ApiError> {
        println!("\nGot query to process: \n{}", post_data);
        let resp = data
            .parse_and_process_queries(post_data.as_bytes())?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    #[post("/register")]
    pub async fn process_reply(
        post_data: String,
        data: web::Data<Witness>,
    ) -> Result<impl Responder, ApiError> {
        println!("\nGot reply to process: \n{}", post_data);
        data.parse_and_process_replies(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    #[post("/forward")]
    pub async fn process_exchange(
        post_data: String,
        data: web::Data<Witness>,
    ) -> Result<impl Responder, ApiError> {
        println!("\nGot exchange to process: \n{}", post_data);
        data.parse_and_process_exchanges(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    #[derive(Debug, Display, Error, From)]
    pub enum ApiError {
        #[display(fmt = "keri error")]
        KeriError(keri::error::Error),

        #[display(fmt = "witness error")]
        WitnessError(WitnessError),

        #[display(fmt = "DB error")]
        DbError(keri::database::DbError),
    }

    impl ResponseError for ApiError {
        fn status_code(&self) -> StatusCode {
            match self {
                ApiError::KeriError(err) => match err {
                    Error::Base64DecodingError { .. }
                    | Error::DeserializeError(_)
                    | Error::IncorrectDigest => StatusCode::BAD_REQUEST,

                    Error::Ed25519DalekSignatureError(_)
                    | Error::FaultySignatureVerification
                    | Error::SignatureVerificationError => StatusCode::FORBIDDEN,

                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },
                ApiError::WitnessError(err) => match err {
                    WitnessError::QueryFailed(err) => match err {
                        SignedQueryError::UnknownSigner { .. } => StatusCode::UNAUTHORIZED,
                        SignedQueryError::QueryError(err) => match err {
                            QueryError::UnknownId { .. } => StatusCode::NOT_FOUND,
                            _ => StatusCode::INTERNAL_SERVER_ERROR,
                        },
                        _ => StatusCode::INTERNAL_SERVER_ERROR,
                    },
                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },
                ApiError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }
    }
}
