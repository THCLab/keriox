use std::{
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::{dev::Server, web::Data, App, HttpServer};
use anyhow::Result;
use keri::{self, error::Error, prefix::BasicPrefix};

use crate::{witness::Witness, witness_processor::WitnessEscrowConfig};

pub struct WitnessListener {
    pub witness_data: Arc<Witness>,
}

impl WitnessListener {
    pub fn setup(
        pub_addr: url::Url,
        event_db_path: &Path,
        priv_key: Option<String>,
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, Error> {
        let mut oobi_path = PathBuf::new();
        oobi_path.push(event_db_path);
        oobi_path.push("oobi");
        Ok(Self {
            witness_data: Arc::new(Witness::setup(
                pub_addr,
                event_db_path,
                oobi_path.as_path(),
                priv_key,
                escrow_config,
            )?),
        })
    }

    pub fn listen_http(&self, addr: impl ToSocketAddrs) -> Server {
        let state = Data::new(self.witness_data.clone());
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .route(
                    "/introduce",
                    actix_web::web::get().to(http_handlers::introduce),
                )
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
                    "/query/tel",
                    actix_web::web::post().to(http_handlers::process_tel_query),
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
        .bind(addr)
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
            error::ActorError,
            parse_event_stream, parse_op_stream,
            simple_controller::{parse_response, PossibleResponse},
        },
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        prefix::IdentifierPrefix,
        query::query_event::{QueryRoute, SignedKelQuery},
    };

    #[async_trait::async_trait]
    impl keri::transport::test::TestActor for super::WitnessListener {
        async fn send_message(&self, msg: Message) -> Result<(), ActorError> {
            let payload = String::from_utf8(msg.to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.witness_data.clone());
            match msg {
                Message::Notice(_) => {
                    super::http_handlers::process_notice(payload, data)
                        .await
                        .map_err(|err| err.0)?;
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        super::http_handlers::process_query(payload, data)
                            .await
                            .map_err(|err| err.0)?;
                    }
                    Op::Reply(_) => {
                        super::http_handlers::process_reply(payload, data)
                            .await
                            .map_err(|err| err.0)?;
                    }
                    Op::Exchange(_) => {
                        super::http_handlers::process_exchange(payload, data)
                            .await
                            .map_err(|err| err.0)?;
                    }
                },
            }

            Ok(())
        }
        async fn send_query(&self, query: SignedKelQuery) -> Result<PossibleResponse, ActorError> {
            let payload =
                String::from_utf8(Message::Op(Op::Query(query.clone())).to_cesr().unwrap())
                    .unwrap();
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::process_query(payload, data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            match query.query.get_route() {
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
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError> {
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::get_eid_oobi(eid.into(), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_op_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }
        async fn request_end_role(
            &self,
            cid: IdentifierPrefix,
            role: Role,
            eid: IdentifierPrefix,
        ) -> Result<Vec<Message>, ActorError> {
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::get_cid_oobi((cid, role, eid).into(), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_event_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }

        async fn resolve_oobi(&self, _msg: keri::oobi::Oobi) -> Result<(), ActorError> {
            todo!()
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
        actor::{error::ActorError, prelude::Message},
        error::Error,
        event_message::signed_event_message::Op,
        oobi::Role,
        prefix::IdentifierPrefix,
    };

    use crate::witness::Witness;

    pub async fn introduce(data: web::Data<Arc<Witness>>) -> Result<HttpResponse, ApiError> {
        Ok(HttpResponse::Ok().json(data.oobi()))
    }

    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        let loc_scheme = data
            .get_loc_scheme_for_id(&eid)
            .map_err(ActorError::KeriError)?
            .unwrap_or_default();
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr().map_err(|_| Error::CesrError)
            })
            .flatten_ok()
            .try_collect()
            .map_err(ActorError::KeriError)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data
            .oobi_manager
            .get_end_role(&cid, role)
            .map_err(ActorError::DbError)?;
        let loc_scheme = data
            .get_loc_scheme_for_id(&eid)
            .map_err(ActorError::KeriError)?
            .unwrap_or_default();
        // (for now) Append controller kel to be able to verify end role signature.
        // TODO use ksn instead
        let oobis = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr().map_err(|_| Error::CesrError)
            })
            .flatten_ok()
            .collect::<Result<Vec<_>, _>>()
            .map_err(ActorError::KeriError)?;
        let res: Vec<_> = data
            .event_storage
            .get_kel_messages_with_receipts(&cid)
            .map_err(ActorError::KeriError)?
            .unwrap_or_default()
            .into_iter()
            .flat_map(|not| Message::Notice(not).to_cesr().unwrap())
            .chain(oobis)
            .collect();

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(res).unwrap()))
    }

    pub async fn process_notice(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nGot notice to process: \n{}", post_data);
        data.parse_and_process_notices(post_data.as_bytes())
            .map_err(ActorError::KeriError)?;
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nGot query to process: \n{}", post_data);
        let resp = data
            .parse_and_process_queries(post_data.as_bytes())?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        println!("\nWitness responds with: {}", resp);
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_tel_query(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nGot query to process: \n{}", post_data);
        let resp = data
            .parse_and_process_tel_queries(post_data.as_bytes())?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        println!("\nWitness responds with: {}", resp);
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_reply(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nGot reply to process: \n{}", post_data);
        data.parse_and_process_replies(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_exchange(
        post_data: String,
        data: web::Data<Arc<Witness>>,
    ) -> Result<HttpResponse, ApiError> {
        println!("\nGot exchange to process: \n{}", post_data);
        data.parse_and_process_exchanges(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    #[derive(Debug, derive_more::Display, derive_more::From, derive_more::Error)]
    pub struct ApiError(pub ActorError);

    impl ResponseError for ApiError {
        fn status_code(&self) -> StatusCode {
            self.0.http_status_code()
        }

        fn error_response(&self) -> HttpResponse {
            HttpResponse::build(self.status_code()).json(&self.0)
        }
    }
}
