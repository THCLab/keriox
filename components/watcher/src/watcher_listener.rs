use std::{path::Path, sync::Arc};

use actix_web::{dev::Server, web, App, HttpServer};
use keri::{error::Error, oobi::LocationScheme, prefix::BasicPrefix};
use keri_transport::default::DefaultTransport;

use crate::watcher::{Watcher, WatcherData, WatcherError};

pub struct WatcherListener {
    watcher_data: Arc<Watcher>,
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

        WatcherData::setup(
            pub_address,
            event_db_path,
            priv_key,
            Box::new(DefaultTransport::new()),
        )
        .map(|watcher_data| Self {
            watcher_data: Arc::new(Watcher(watcher_data)),
        })
    }

    pub fn listen_http(self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(self.watcher_data);
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
                    "/resolve",
                    actix_web::web::post().to(http_handlers::resolve_oobi),
                )
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub async fn resolve_initial_oobis(
        &self,
        initial_oobis: &[LocationScheme],
    ) -> Result<(), WatcherError> {
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
        error::Error,
        event_message::cesr_adapter::ParsedEvent,
        event_parsing::primitives::CesrPrimitive,
        oobi::{error::OobiError, EndRole, LocationScheme, Role},
        prefix::IdentifierPrefix,
    };
    use reqwest::StatusCode;
    use serde::Deserialize;

    use crate::watcher::{Watcher, WatcherError};

    pub async fn process_notice(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, WatcherError> {
        println!(
            "\nGot events to process: \n{}",
            String::from_utf8_lossy(&body)
        );
        data.0.parse_and_process_notices(&body)?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query(
        body: web::Bytes,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, WatcherError> {
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
    ) -> Result<HttpResponse, WatcherError> {
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
    ) -> Result<HttpResponse, WatcherError> {
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
            .map_err(|err| WatcherError::KeriError(Error::JsonDeserError))?
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
    ) -> Result<HttpResponse, WatcherError> {
        let loc_scheme = data.0.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed: ParsedEvent = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten()
            .collect();
        println!(
            "\nSending {} oobi: {}",
            &eid.to_str(),
            String::from_utf8(oobis.clone()).unwrap_or_default()
        );
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap()))
    }

    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Watcher>>,
    ) -> Result<HttpResponse, WatcherError> {
        let (cid, role, eid) = path.into_inner();

        let end_role = data.0.oobi_manager.get_end_role(&cid, role)?;
        let loc_scheme = data.0.get_loc_scheme_for_id(&eid)?;
        let oobis: Vec<u8> = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: ParsedEvent = sr.into();
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

    impl ResponseError for WatcherError {
        fn status_code(&self) -> StatusCode {
            match self {
                WatcherError::DbError(_) => StatusCode::INTERNAL_SERVER_ERROR,

                WatcherError::KeriError(err) => match err {
                    Error::Base64DecodingError { .. }
                    | Error::DeserializeError(_)
                    | Error::IncorrectDigest => StatusCode::BAD_REQUEST,

                    Error::Ed25519DalekSignatureError
                    | Error::FaultySignatureVerification
                    | Error::SignatureVerificationError => StatusCode::FORBIDDEN,

                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },

                WatcherError::OobiError(err) => match err {
                    OobiError::SignerMismatch => StatusCode::FORBIDDEN,

                    _ => StatusCode::INTERNAL_SERVER_ERROR,
                },

                _ => StatusCode::INTERNAL_SERVER_ERROR,
            }
        }

        fn error_response(&self) -> HttpResponse {
            HttpResponse::build(self.status_code()).json(self)
        }
    }
}

mod test {
    use actix_web::{body::MessageBody, web::Bytes};
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

    use crate::WatcherError;

    #[async_trait::async_trait]
    impl keri_transport::test::TestActor<WatcherError> for super::WatcherListener {
        async fn send_message(&self, msg: Message) -> Result<(), WatcherError> {
            let payload = String::from_utf8(msg.to_cesr().unwrap()).unwrap();
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            match msg {
                Message::Notice(_) => {
                    super::http_handlers::process_notice(Bytes::from(payload), data).await?;
                }
                Message::Op(op) => match op {
                    Op::Query(_) => {
                        super::http_handlers::process_query(Bytes::from(payload), data).await?;
                    }
                    Op::Reply(_) => {
                        super::http_handlers::process_reply(Bytes::from(payload), data).await?;
                    }
                    Op::Exchange(_) => {
                        panic!("watcher doesn't support exchange")
                    }
                },
            }

            Ok(())
        }
        async fn send_query(&self, query: SignedQuery) -> Result<PossibleResponse, WatcherError> {
            let payload =
                String::from_utf8(Message::Op(Op::Query(query.clone())).to_cesr().unwrap())
                    .unwrap();
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            let resp = super::http_handlers::process_query(Bytes::from(payload), data).await?;
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
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, WatcherError> {
            let data = actix_web::web::Data::new(self.watcher_data.clone());
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
        ) -> Result<Vec<Message>, WatcherError> {
            let data = actix_web::web::Data::new(self.watcher_data.clone());
            let resp = super::http_handlers::get_cid_oobi((cid, role, eid).into(), data).await?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            let resp = parse_event_stream(resp.as_ref()).unwrap();
            Ok(resp)
        }
    }
}
