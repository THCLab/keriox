use crate::http_routing::configure_routes;
use std::{net::ToSocketAddrs, sync::Arc};

use actix_web::{dev::Server, rt::spawn, web, App, HttpServer};
use keri_core::{actor::error::ActorError, oobi::LocationScheme, oobi_manager::RedbOobiStorage, oobi_manager::storage::OobiStorageBackend, prefix::BasicPrefix};

use crate::{watcher::Watcher, WatcherConfig};

use self::http_handlers::ApiError;

pub struct WatcherListener<S: OobiStorageBackend> {
    pub watcher: Arc<Watcher<S>>,
}

impl<S: OobiStorageBackend + 'static> WatcherListener<S> {
    pub fn new(config: WatcherConfig, oobi_manager: keri_core::oobi_manager::OobiManager<S>) -> Result<Self, ActorError> {
        Ok(Self {
            watcher: Arc::new(Watcher::new(config, oobi_manager)?),
        })
    }

    pub fn listen_http(self, addr: impl ToSocketAddrs) -> Server {
        let data = self.watcher.clone();
        spawn(update_tel_checking(data.clone()));
        spawn(update_checking(data));

        let state = web::Data::new(self.watcher);
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .configure(configure_routes)
        })
        .bind(addr)
        .unwrap()
        .run()
    }
}

impl WatcherListener<RedbOobiStorage> {
    pub fn setup_with_redb(config: WatcherConfig) -> Result<Self, ActorError> {
        use std::path::PathBuf;
        use keri_core::{database::redb::RedbDatabase, oobi_manager::RedbOobiManager};

        // Create oobi manager database in a separate location
        let mut oobi_db_path = config.db_path.clone();
        oobi_db_path.push("oobi_database");
        let oobi_db = Arc::new(RedbDatabase::new(&oobi_db_path).unwrap());
        let oobi_manager = RedbOobiManager::new(oobi_db)?;
        Self::new(config, oobi_manager)
    }
}

impl<S: OobiStorageBackend> WatcherListener<S> {
    pub async fn resolve_initial_oobis(
        &self,
        initial_oobis: &[LocationScheme],
    ) -> Result<(), ApiError> {
        for lc in initial_oobis.iter() {
            self.watcher.resolve_loc_scheme(lc).await?;
        }

        Ok(())
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.watcher.prefix()
    }
}

pub async fn update_checking<S: OobiStorageBackend>(data: Arc<Watcher<S>>) {
    data.process_update_requests().await;
}

pub async fn update_tel_checking<S: OobiStorageBackend>(data: Arc<Watcher<S>>) {
    let _ = data.process_update_tel_requests().await;
}

pub mod http_handlers {

    use std::sync::Arc;

    use actix_web::{
        http::{header::ContentType, StatusCode},
        web, HttpResponse, Responder, ResponseError,
    };
    use itertools::Itertools;
    use keri_core::{
        actor::{error::ActorError, prelude::Message},
        event_message::signed_event_message::Op,
        oobi::{error::OobiError, EndRole, LocationScheme, Role},
        oobi_manager::RedbOobiStorage,
        oobi_manager::storage::OobiStorageBackend,
        prefix::IdentifierPrefix,
    };
    use serde::Deserialize;

    use crate::watcher::Watcher;

    pub async fn introduce<S: OobiStorageBackend>(data: web::Data<Arc<Watcher<S>>>) -> Result<HttpResponse, ApiError> {
        Ok(HttpResponse::Ok().json(data.oobi()))
    }

    pub async fn process_notice<S: OobiStorageBackend>(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing notice");
        tracing::debug!(payload = %String::from_utf8_lossy(&body), "Notice payload");
        data.parse_and_process_notices(&body)
            .map_err(ActorError::from)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query<S: OobiStorageBackend>(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing query");
        tracing::debug!(payload = %String::from_utf8_lossy(&body), "Query payload");
        let resp = data
            .parse_and_process_queries(&body)
            .await?
            .iter()
            .map(|msg| msg.to_string())
            .join("");
        tracing::debug!(response = %resp, "Query response");

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_reply<S: OobiStorageBackend>(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing reply");
        tracing::debug!(payload = %String::from_utf8_lossy(&body), "Reply payload");

        data.parse_and_process_replies(&body)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn resolve_oobi<S: OobiStorageBackend>(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Resolving OOBI");
        tracing::debug!(payload = %String::from_utf8_lossy(&body), "OOBI payload");

        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum RequestData {
            EndRole(EndRole),
            LocationScheme(LocationScheme),
        }

        match serde_json::from_slice(&body).map_err(|_| {
            ApiError(OobiError::Parse(String::from_utf8_lossy(&body).to_string()).into())
        })? {
            RequestData::EndRole(end_role) => {
                data.resolve_end_role(end_role).await?;
            }
            RequestData::LocationScheme(loc_scheme) => {
                data.resolve_loc_scheme(&loc_scheme).await?;
            }
        }

        Ok(HttpResponse::Ok().finish())
    }

    pub async fn resolve_location<S: OobiStorageBackend>(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        let loc_scheme = data.signed_location(&eid)?;
        let oobis = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr()
            })
            .flatten_ok()
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| ApiError(ActorError::GeneralError(e.to_string())))?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn resolve_role<S: OobiStorageBackend>(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data.watcher_data.get_end_role_for_id(&cid, role)?;
        let loc_scheme = data.watcher_data.get_loc_scheme_for_id(&eid)?;
        let oobis = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed = Message::Op(Op::Reply(sr));
                sed.to_cesr()
            })
            .flatten_ok()
            .collect::<Result<Vec<u8>, _>>()
            .map_err(|e| ApiError(ActorError::GeneralError(e.to_string())))?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn process_tel_query<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Watcher<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing TEL query");
        tracing::debug!(payload = %post_data, "TEL query payload");
        let resp = data
            .parse_and_process_tel_queries(post_data.as_bytes())
            .await?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        tracing::debug!(response = %resp, "TEL query response");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
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

    // Concrete wrapper functions for Redb backend (used for HTTP routing)
    pub async fn introduce_redb(data: web::Data<Arc<Watcher<RedbOobiStorage>>>) -> Result<HttpResponse, ApiError> {
        introduce(data).await
    }

    pub async fn process_notice_redb(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_notice(body, data).await
    }

    pub async fn process_query_redb(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_query(body, data).await
    }

    pub async fn process_reply_redb(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_reply(body, data).await
    }

    pub async fn resolve_oobi_redb(
        body: web::Bytes,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        resolve_oobi(body, data).await
    }

    pub async fn resolve_location_redb(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        resolve_location(eid, data).await
    }

    pub async fn resolve_role_redb(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        resolve_role(path, data).await
    }

    pub async fn process_tel_query_redb(
        post_data: String,
        data: web::Data<Arc<Watcher<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_tel_query(post_data, data).await
    }

    pub async fn info() -> impl Responder {
        let version = option_env!("CARGO_PKG_VERSION");
        if let Some(version) = version {
            HttpResponse::Ok().json(serde_json::json!({ "version": version }))
        } else {
            HttpResponse::InternalServerError()
                .json(serde_json::json!({ "error": "Failed to retrieve version information" }))
        }
    }
}

mod test {
    use actix_web::{body::MessageBody, web::Bytes};
    use keri_core::{
        actor::{
            error::ActorError, parse_event_stream, parse_op_stream,
            possible_response::PossibleResponse,
        },
        event_message::signed_event_message::{Message, Op},
        oobi::{Oobi, Role},
        oobi_manager::storage::OobiStorageBackend,
        prefix::IdentifierPrefix,
        query::query_event::{QueryRoute, SignedQueryMessage},
    };

    #[async_trait::async_trait]
    impl<S: OobiStorageBackend> keri_core::transport::test::TestActor for super::WatcherListener<S> {
        async fn send_message(&self, msg: Message) -> Result<(), ActorError> {
            let payload = String::from_utf8(msg.to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.watcher.clone());
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
        async fn send_query(
            &self,
            query: SignedQueryMessage,
        ) -> Result<PossibleResponse, ActorError> {
            let payload =
                String::from_utf8(Message::from(query.clone()).to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.watcher.clone());
            let resp = super::http_handlers::process_query(Bytes::from(payload), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            if let SignedQueryMessage::KelQuery(qry) = query {
                match qry.query.get_route() {
                    QueryRoute::Ksn { .. } => {
                        let resp = parse_op_stream(&resp).unwrap();
                        let resp = resp.into_iter().next().unwrap();
                        let Op::Reply(reply) = resp else {
                            panic!("wrong response type")
                        };
                        Ok(PossibleResponse::Ksn(reply))
                    }
                    QueryRoute::Logs { .. } => {
                        let log = parse_event_stream(&resp).unwrap();
                        Ok(PossibleResponse::Kel(log))
                    }
                }
            } else {
                panic!("unexpected query type")
            }
        }
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError> {
            let data = actix_web::web::Data::new(self.watcher.clone());
            let resp = super::http_handlers::resolve_location(eid.into(), data)
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
        ) -> Result<Vec<u8>, ActorError> {
            let data = actix_web::web::Data::new(self.watcher.clone());
            let resp = super::http_handlers::resolve_role((cid, role, eid).into(), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            Ok(resp.to_vec())
        }
        async fn resolve_oobi(&self, msg: Oobi) -> Result<(), ActorError> {
            let data = actix_web::web::Data::new(self.watcher.clone());
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
