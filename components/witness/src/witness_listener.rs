use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::{dev::Server, web::Data, App, HttpServer};
use anyhow::Result;
use keri::{self, error::Error, prefix::BasicPrefix};

use crate::witness::Witness;

pub struct WitnessListener {
    pub witness_data: Arc<Witness>,
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
            address
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
                .route(
                    "/oobi/{id}",
                    actix_web::web::get().to(http_handlers::get_eid_oobi),
                )
                .route(
                    "/oobi/{cid}/{role}/{eid}",
                    actix_web::web::get().to(http_handlers::get_cid_oobi),
                )
                .route(
                    "/process",
                    actix_web::web::post().to(http_handlers::process_notice),
                )
                .route(
                    "/query",
                    actix_web::web::post().to(http_handlers::process_query),
                )
                .route(
                    "/register",
                    actix_web::web::post().to(http_handlers::process_reply),
                )
                .route(
                    "/forward",
                    actix_web::web::post().to(http_handlers::process_exchange),
                )
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.witness_data.prefix.clone()
    }
}

mod test {
    use actix_web::body::MessageBody;
    use keri::{
        actor::{
            parse_event_stream, parse_op_stream,
            simple_controller::{parse_response, PossibleResponse},
        },
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        prefix::IdentifierPrefix,
        query::query_event::{QueryRoute, SignedQuery},
    };

    use crate::WitnessError;

    #[async_trait::async_trait]
    impl keri_transport::test::TestActor<WitnessError> for super::WitnessListener {
        async fn send_message(&self, msg: Message) -> Result<(), WitnessError> {
            let payload = String::from_utf8(msg.to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.witness_data.clone());
            match msg {
                Message::Notice(_) => {
                    super::http_handlers::process_notice(payload, data).await?;
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        super::http_handlers::process_query(payload, data).await?;
                    }
                    Op::Reply(_) => {
                        super::http_handlers::process_reply(payload, data).await?;
                    }
                    Op::Exchange(_) => {
                        super::http_handlers::process_exchange(payload, data).await?;
                    }
                },
            }

            Ok(())
        }
        async fn send_query(&self, query: SignedQuery) -> Result<PossibleResponse, WitnessError> {
            let payload =
                String::from_utf8(Message::Op(Op::Query(query.clone())).to_cesr().unwrap())
                    .unwrap();
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::process_query(payload, data).await?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            match query.query.event.content.data.route {
                QueryRoute::Ksn { .. } => {
                    let resp = parse_op_stream(&resp).unwrap();
                    let resp = resp.into_iter().next().unwrap();
                    let Op::Reply(reply) = resp else { panic!("wrong response type") };
                    Ok(PossibleResponse::Ksn(reply))
                }
                QueryRoute::Log { .. } => {
                    let log = parse_event_stream(&resp).unwrap();
                    Ok(PossibleResponse::Kel(log))
                }
                QueryRoute::Mbx { .. } => {
                    let resp = String::from_utf8(resp.to_vec()).unwrap();
                    let resp = parse_response(&resp).unwrap();
                    Ok(resp)
                }
            }
        }
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, WitnessError> {
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::get_eid_oobi(eid.into(), data).await?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_op_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }
        async fn request_end_role(
            &self,
            cid: IdentifierPrefix,
            role: Role,
            eid: IdentifierPrefix,
        ) -> Result<Vec<Message>, WitnessError> {
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::get_cid_oobi((cid, role, eid).into(), data).await?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_event_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }
    }
}

pub mod http_handlers {
    use std::sync::Arc;

    use actix_web::{
        http::{header::ContentType, StatusCode},
        web, HttpResponse, ResponseError,
    };
    use itertools::Itertools;
    use keri::{
        actor::{QueryError, SignedQueryError, prelude::Message},
        error::Error,
        event_message::cesr_adapter::ParsedEvent,
        event_parsing::primitives::CesrPrimitive,
        oobi::Role,
        prefix::IdentifierPrefix,
    };

    use crate::witness::{Witness, WitnessError};

    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
        let loc_scheme = data
            .get_loc_scheme_for_id(&eid)
            .map_err(WitnessError::KeriError)?
            .unwrap_or_default();
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed: ParsedEvent = sr.into();
                sed.to_cesr().map_err(|_| Error::CesrError)
            })
            .flatten_ok()
            .try_collect()
            .map_err(WitnessError::KeriError)?;

        println!(
            "\nSending {} oobi: \n {}",
            &eid.to_str(),
            String::from_utf8(oobis.clone()).unwrap_or_default()
        );
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data
            .oobi_manager
            .get_end_role(&cid, role)
            .map_err(WitnessError::DbError)?;
        let loc_scheme = data
            .get_loc_scheme_for_id(&eid)
            .map_err(WitnessError::KeriError)?
            .unwrap_or_default();
        // (for now) Append controller kel to be able to verify end role signature.
        // TODO use ksn instead
        let cont_kel: Vec<_> = data
            .event_storage
            .get_kel_messages_with_receipts(&cid)
            .map_err(WitnessError::KeriError)?
            .unwrap_or_default()
            .into_iter()
            .map(|not| Message::Notice(not).to_cesr().unwrap())
            .flatten()
            .collect();
        let oobis = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: ParsedEvent = sr.into();
                sed.to_cesr().map_err(|_| Error::CesrError)
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, _>>()
            .map_err(WitnessError::KeriError)?;
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

    pub async fn process_notice(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
        println!("\nGot notice to process: \n{}", post_data);
        data.parse_and_process_notices(post_data.as_bytes())
            .map_err(WitnessError::KeriError)?;
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
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

    pub async fn process_reply(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
        println!("\nGot reply to process: \n{}", post_data);
        data.parse_and_process_replies(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_exchange(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, WitnessError> {
        println!("\nGot exchange to process: \n{}", post_data);
        data.parse_and_process_exchanges(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    impl ResponseError for WitnessError {
        fn status_code(&self) -> StatusCode {
            match self {
                WitnessError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,

                WitnessError::QueryFailed(err) => match err {
                    SignedQueryError::KeriError(_) | SignedQueryError::DbError(_) => {
                        StatusCode::INTERNAL_SERVER_ERROR
                    }

                    SignedQueryError::UnknownSigner { .. } | SignedQueryError::InvalidSignature => {
                        StatusCode::UNAUTHORIZED
                    }

                    SignedQueryError::QueryError(err) => match err {
                        QueryError::KeriError(_) | QueryError::DbError(_) => {
                            StatusCode::INTERNAL_SERVER_ERROR
                        }

                        QueryError::UnknownId { .. } => StatusCode::NOT_FOUND,
                    },
                },

                WitnessError::KeriError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }

        fn error_response(&self) -> HttpResponse {
            HttpResponse::build(self.status_code()).json(self)
        }
    }
}
