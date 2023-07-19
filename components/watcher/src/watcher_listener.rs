use std::{net::ToSocketAddrs, sync::Arc};

use actix_web::{dev::Server, web, App, HttpServer};
use keri::{error::Error, oobi::LocationScheme, prefix::BasicPrefix};

use crate::watcher::{Watcher, WatcherConfig, WatcherData};

use self::http_handlers::ApiError;

pub struct WatcherListener {
    pub watcher_data: Arc<Watcher>,
}

impl WatcherListener {
    pub fn new(config: WatcherConfig) -> Result<Self, Error> {
        Ok(Self {
            watcher_data: Arc::new(Watcher(WatcherData::new(config)?)),
        })
    }

    pub fn listen_http(self, addr: impl ToSocketAddrs) -> Server {
        let state = web::Data::new(self.watcher_data);
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
                    "/register",
                    actix_web::web::post().to(http_handlers::process_reply),
                )
                .route(
                    "/resolve",
                    actix_web::web::post().to(http_handlers::resolve_oobi),
                )
        })
        .bind(addr)
        .unwrap()
        .run()
    }

    pub async fn resolve_initial_oobis(
        &self,
        initial_oobis: &[LocationScheme],
    ) -> Result<(), ApiError> {
        for lc in initial_oobis.iter() {
            self.watcher_data.resolve_loc_scheme(lc).await?;
        }

        Ok(())
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.watcher_data.0.prefix.clone()
    }
}

pub mod http_handlers {

    use std::sync::Arc;

    use actix_web::{http::header::ContentType, web, HttpResponse, ResponseError};
    use itertools::Itertools;
    use keri::{
        actor::{error::ActorError, prelude::Message},
        error::Error,
        event_message::signed_event_message::Op,
        oobi::{EndRole, LocationScheme, Role},
        prefix::IdentifierPrefix,
    };
    use reqwest::StatusCode;
    use serde::Deserialize;

    use crate::watcher::Watcher;

    pub async fn introduce(data: web::Data<Arc<Watcher>>) -> Result<HttpResponse, ApiError> {
        Ok(HttpResponse::Ok().json(data.oobi()))
    }

    pub async fn process_notice(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
        println!(
            "\nGot events to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        data.0
            .parse_and_process_notices(&body)
            .map_err(ActorError::from)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
        println!(
            "\nGot queries to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        let resp = data
            .0
            .parse_and_process_queries(&body)
            .await?
            .iter()
            .map(|msg| msg.to_string())
            .join("");

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_reply(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
        println!(
            "\nGot replies to process: \n{}",
            String::from_utf8_lossy(&body)
        );

        data.0.parse_and_process_replies(&body)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn resolve_oobi(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
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

        match serde_json::from_slice(&body)
            .map_err(|_| ActorError::KeriError(Error::JsonDeserError))?
        {
            RequestData::EndRole(end_role) => {
                data.resolve_end_role(end_role).await?;
            }
            RequestData::LocationScheme(loc_scheme) => {
                data.resolve_loc_scheme(&loc_scheme).await?;
            }
        }

        Ok(HttpResponse::Ok().finish())
    }

    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
        let loc_scheme = data.0.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .flat_map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr().unwrap()
            })
            .collect();

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data
            .0
            .oobi_manager
            .get_end_role(&cid, role)
            .map_err(ActorError::from)?;
        let loc_scheme = data.0.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .flat_map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr().unwrap()
            })
            .collect();

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
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

mod test {
    use actix_web::{body::MessageBody, web::Bytes};
    use keri::{
        actor::{
            error::ActorError,
            parse_event_stream, parse_op_stream,
            simple_controller::{parse_response, PossibleResponse},
        },
        event_message::signed_event_message::{Message, Op},
        oobi::{Oobi, Role},
        prefix::IdentifierPrefix,
        query::query_event::{QueryRoute, SignedKelQuery},
    };

    #[async_trait::async_trait]
    impl keri::transport::test::TestActor for super::WatcherListener {
        async fn send_message(&self, msg: Message) -> Result<(), ActorError> {
            let payload = String::from_utf8(msg.to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            match msg {
                Message::Notice(_) => {
                    super::http_handlers::process_notice(Bytes::from(payload), data)
                        .await
                        .map_err(|err| err.0)?;
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        super::http_handlers::process_query(Bytes::from(payload), data)
                            .await
                            .map_err(|err| err.0)?;
                    }
                    Op::Reply(_) => {
                        super::http_handlers::process_reply(Bytes::from(payload), data)
                            .await
                            .map_err(|err| err.0)?;
                    }
                    Op::Exchange(_) => {
                        panic!("watcher doesn't support exchange")
                    }
                },
            }

            Ok(())
        }
        async fn send_query(&self, query: SignedKelQuery) -> Result<PossibleResponse, ActorError> {
            let payload =
                String::from_utf8(Message::Op(Op::Query(query.clone())).to_cesr().unwrap())
                    .unwrap();
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            let resp = super::http_handlers::process_query(Bytes::from(payload), data)
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
            let data = actix_web::web::Data::new(self.watcher_data.clone());
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
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            let resp = super::http_handlers::get_cid_oobi((cid, role, eid).into(), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_event_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }
        async fn resolve_oobi(&self, msg: Oobi) -> Result<(), ActorError> {
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            let resp = super::http_handlers::resolve_oobi(
                Bytes::from(serde_json::to_string(&msg).unwrap()),
                data,
            )
            .await
            .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            parse_event_stream(resp.as_ref()).unwrap();
            Ok(())
        }
    }
}
