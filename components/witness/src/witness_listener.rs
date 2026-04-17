use std::{
    net::ToSocketAddrs,
    path::{Path, PathBuf},
    sync::Arc,
};

use actix_web::{dev::Server, web::Data, App, HttpServer};
use anyhow::Result;
use keri_core::{
    self, oobi_manager::storage::OobiStorageBackend, oobi_manager::RedbOobiStorage,
    prefix::BasicPrefix,
};

use crate::{
    witness::{Witness, WitnessError},
    witness_processor::WitnessEscrowConfig,
};

pub struct WitnessListener<S: OobiStorageBackend> {
    pub witness_data: Arc<Witness<S>>,
}

impl<S: OobiStorageBackend + 'static> WitnessListener<S> {
    pub fn setup(
        pub_addr: url::Url,
        event_db_path: &Path,
        priv_key: Option<String>,
        escrow_config: WitnessEscrowConfig,
        oobi_manager: keri_core::oobi_manager::OobiManager<S>,
    ) -> Result<Self, WitnessError> {
        let mut oobi_path = PathBuf::new();
        oobi_path.push(event_db_path);
        oobi_path.push("oobi");
        let signer = match priv_key {
            Some(key) => {
                Arc::new(keri_core::signer::Signer::new_with_seed(&key.parse().unwrap()).unwrap())
            }
            None => Arc::new(keri_core::signer::Signer::new()),
        };
        Ok(Self {
            witness_data: Arc::new(Witness::new(
                pub_addr,
                signer,
                event_db_path,
                escrow_config,
                oobi_manager,
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
                    actix_web::web::get().to(http_handlers::introduce_redb),
                )
                .route(
                    "/oobi/{id}",
                    actix_web::web::get().to(http_handlers::resolve_location_redb),
                )
                .route(
                    "/oobi/{cid}/{role}/{eid}",
                    actix_web::web::get().to(http_handlers::resolve_role_redb),
                )
                .route(
                    "/process",
                    actix_web::web::post().to(http_handlers::process_notice_redb),
                )
                .route(
                    "/query",
                    actix_web::web::post().to(http_handlers::process_query_redb),
                )
                .route(
                    "/query/tel",
                    actix_web::web::post().to(http_handlers::process_tel_query_redb),
                )
                .route(
                    "/process/tel",
                    actix_web::web::post().to(http_handlers::process_tel_events_redb),
                )
                .route(
                    "/register",
                    actix_web::web::post().to(http_handlers::process_reply_redb),
                )
                .route(
                    "/forward",
                    actix_web::web::post().to(http_handlers::process_exchange_redb),
                )
                .route("/info", actix_web::web::get().to(http_handlers::info))
        })
        .bind(addr)
        .unwrap()
        .run()
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.witness_data.prefix.clone()
    }
}

impl WitnessListener<RedbOobiStorage> {
    pub fn setup_with_redb(
        pub_addr: url::Url,
        event_db_path: &Path,
        priv_key: Option<String>,
        escrow_config: WitnessEscrowConfig,
    ) -> Result<Self, WitnessError> {
        use keri_core::{database::redb::RedbDatabase, oobi_manager::RedbOobiManager};

        // Create oobi manager database in a separate location
        let oobi_db_path = event_db_path.join("oobi_database");
        let oobi_db = Arc::new(RedbDatabase::new(&oobi_db_path).unwrap());
        let oobi_manager = RedbOobiManager::new(oobi_db)?;

        let signer = Arc::new(
            priv_key
                .as_ref()
                .map(|key| keri_core::signer::Signer::new_with_seed(&key.parse().unwrap()))
                .unwrap_or_else(|| Ok(keri_core::signer::Signer::new()))?,
        );
        let prefix = keri_core::prefix::BasicPrefix::Ed25519NT(signer.public_key());

        // construct witness loc scheme oobi
        let loc_scheme = keri_core::oobi::LocationScheme::new(
            keri_core::prefix::IdentifierPrefix::Basic(prefix.clone()),
            pub_addr.scheme().parse().unwrap(),
            pub_addr.clone(),
        );
        let witness = Self::setup(
            pub_addr,
            event_db_path,
            priv_key,
            escrow_config,
            oobi_manager,
        )?;

        let reply = keri_core::query::reply_event::ReplyEvent::new_reply(
            keri_core::query::reply_event::ReplyRoute::LocScheme(loc_scheme),
            keri_core::actor::prelude::HashFunctionCode::Blake3_256,
            keri_core::actor::prelude::SerializationFormats::JSON,
        );
        let signed_reply = keri_core::query::reply_event::SignedReply::new_nontrans(
            reply.clone(),
            prefix,
            keri_core::prefix::SelfSigningPrefix::Ed25519Sha512(
                signer
                    .sign(reply.encode().unwrap())
                    .map_err(|_e| WitnessError::SigningError)?,
            ),
        );
        witness.witness_data.oobi_manager.save_oobi(&signed_reply)?;

        Ok(witness)
    }
}

mod test {
    use actix_web::body::MessageBody;
    use keri_core::{
        actor::{
            error::ActorError,
            parse_event_stream, parse_op_stream,
            possible_response::{parse_response, PossibleResponse},
        },
        event_message::signed_event_message::{Message, Op},
        oobi::Role,
        oobi_manager::storage::OobiStorageBackend,
        prefix::IdentifierPrefix,
        query::{
            self,
            query_event::{QueryRoute, SignedQueryMessage},
        },
    };

    #[async_trait::async_trait]
    impl<S: OobiStorageBackend> keri_core::transport::test::TestActor for super::WitnessListener<S> {
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
        async fn send_query(
            &self,
            query: SignedQueryMessage,
        ) -> Result<PossibleResponse, ActorError> {
            let payload =
                String::from_utf8(Message::Op(Op::Query(query.clone())).to_cesr().unwrap())
                    .unwrap();

            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::process_query(payload, data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            match query {
                SignedQueryMessage::KelQuery(qry) => match qry.query.get_route() {
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
                },
                SignedQueryMessage::MailboxQuery(qry) => match qry.query.data.data {
                    query::mailbox::MailboxRoute::Mbx {
                        reply_route: _,
                        args: _,
                    } => {
                        let resp = String::from_utf8(resp.to_vec()).unwrap();
                        let resp = parse_response(&resp).unwrap();
                        Ok(resp)
                    }
                }, // },
            }
        }
        async fn request_loc_scheme(&self, eid: IdentifierPrefix) -> Result<Vec<Op>, ActorError> {
            let data = actix_web::web::Data::new(self.witness_data.clone());
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
            let data = actix_web::web::Data::new(self.witness_data.clone());
            let resp = super::http_handlers::resolve_role((cid, role, eid).into(), data)
                .await
                .map_err(|err| err.0)?;
            let resp = resp.into_body().try_into_bytes().unwrap();
            Ok(resp.to_vec())
        }

        async fn resolve_oobi(&self, _msg: keri_core::oobi::Oobi) -> Result<(), ActorError> {
            todo!()
        }
    }
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
        error::Error,
        event_message::signed_event_message::Op,
        oobi::Role,
        oobi_manager::storage::OobiStorageBackend,
        oobi_manager::RedbOobiStorage,
        prefix::{CesrPrimitive, IdentifierPrefix},
    };
    use teliox::event::verifiable_event::VerifiableEvent;

    use crate::witness::Witness;

    pub async fn introduce<S: OobiStorageBackend>(
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        Ok(HttpResponse::Ok().json(data.oobi()))
    }

    pub async fn resolve_location<S: OobiStorageBackend>(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        let loc_scheme = data
            .get_loc_scheme_for_id(&eid)
            .map_err(ActorError::KeriError)?;
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

    pub async fn resolve_role<S: OobiStorageBackend>(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        let (cid, role, eid) = path.into_inner();
        let out = if role == Role::Witness {
            // Check if it is TEL identifier
            let management_tel = data.tel.get_management_tel(&cid).unwrap();
            match management_tel {
                // Then return TEL
                Some(management_tel) => Ok(management_tel
                    .map(|tel_event| tel_event.serialize().unwrap())
                    .flatten()
                    .collect()),
                // Otherwise return location and KEL
                None => {
                    let location_signed = data
                        .get_loc_scheme_for_id(&eid)
                        .map_err(ActorError::KeriError)?
                        .into_iter()
                        .flat_map(|location| {
                            let sed = Message::Op(Op::Reply(location));
                            sed.to_cesr().map_err(|_| Error::CesrError).unwrap()
                        });

                    Ok(data
                        .event_storage
                        .get_kel_messages_with_receipts_all(&cid)
                        .map_err(ActorError::KeriError)?
                        .unwrap_or_default()
                        .into_iter()
                        .flat_map(|not| Message::Notice(not).to_cesr().unwrap())
                        .chain(location_signed)
                        .collect::<Vec<_>>())
                }
            }
        } else {
            let end_role = data
                .oobi_manager
                .get_end_role(&cid, role.clone())
                .map_err(|e| ActorError::DbError(e.to_string()))?;
            match end_role {
                Some(role_oobi) => {
                    let location_signed = data
                        .get_loc_scheme_for_id(&eid)
                        .map_err(ActorError::KeriError)?;
                    // Join end role OOBI with location OOBIs and serialize to CESR.
                    let oobis = role_oobi
                        .into_iter()
                        .chain(location_signed.into_iter())
                        .map(|sr| {
                            let sed = Message::Op(Op::Reply(sr));
                            sed.to_cesr().map_err(|_| Error::CesrError)
                        })
                        .flatten_ok()
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(ActorError::KeriError)?;

                    // (for now) Append controller kel to be able to verify end role signature.
                    // TODO use ksn instead
                    Ok(data
                        .event_storage
                        .get_kel_messages_with_receipts_all(&cid)
                        .map_err(ActorError::KeriError)?
                        .unwrap_or_default()
                        .into_iter()
                        .flat_map(|not| Message::Notice(not).to_cesr().unwrap())
                        .chain(oobis)
                        .collect::<Vec<_>>())
                }
                None => Err(ApiError(ActorError::MissingRole { role, id: cid })),
            }
        };

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(out?).unwrap()))
    }

    pub async fn process_notice<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!(witness = %data.prefix.to_str(), "Processing notice");
        tracing::debug!(payload = %post_data, "Notice payload");
        data.parse_and_process_notices(post_data.as_bytes())
            .map_err(ActorError::KeriError)?;
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_query<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        eprintln!("[DEBUG-WITNESS] process_query received: {} bytes", post_data.len());
        tracing::info!(witness = %data.prefix.to_str(), "Processing query");
        tracing::debug!(payload = %post_data, "Query payload");
        let resp = data
            .parse_and_process_queries(post_data.as_bytes())
            .map_err(|e| { eprintln!("[DEBUG-WITNESS] parse_and_process_queries error: {:?}", e); ApiError(e) })?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        tracing::debug!(response = %resp, "Query response");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_tel_query<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing TEL query");
        tracing::debug!(payload = %post_data, "TEL query payload");
        let resp = data
            .parse_and_process_tel_queries(post_data.as_bytes())?
            .iter()
            .map(|msg| msg.to_string())
            .collect::<Vec<_>>()
            .join("");
        tracing::debug!(response = %resp, "TEL query response");
        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp))
    }

    pub async fn process_reply<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing reply");
        tracing::debug!(payload = %post_data, "Reply payload");
        data.parse_and_process_replies(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_exchange<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing exchange");
        tracing::debug!(payload = %post_data, "Exchange payload");
        data.parse_and_process_exchanges(post_data.as_bytes())?;

        Ok(HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(()))
    }

    pub async fn process_tel_events<S: OobiStorageBackend>(
        post_data: String,
        data: web::Data<Arc<Witness<S>>>,
    ) -> Result<HttpResponse, ApiError> {
        tracing::info!("Processing TEL event");
        tracing::debug!(payload = %post_data, "TEL event payload");
        let parsed = VerifiableEvent::parse(post_data.as_bytes()).unwrap();
        for ev in parsed {
            data.tel.processor.process(ev).unwrap()
        }

        Ok(HttpResponse::Ok().body(()))
    }

    pub async fn info() -> impl Responder {
        let version = env!("CARGO_PKG_VERSION");
        let git_suffix = option_env!("GIT_VERSION_SUFFIX").unwrap_or("");
        let full_version = format!("{version}{git_suffix}");
        HttpResponse::Ok().json(serde_json::json!({ "version": full_version }))
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
    pub async fn introduce_redb(
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        introduce(data).await
    }

    pub async fn process_notice_redb(
        body: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_notice(body, data).await
    }

    pub async fn process_query_redb(
        body: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_query(body, data).await
    }

    pub async fn process_tel_query_redb(
        post_data: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_tel_query(post_data, data).await
    }

    pub async fn process_reply_redb(
        body: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_reply(body, data).await
    }

    pub async fn process_exchange_redb(
        post_data: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_exchange(post_data, data).await
    }

    pub async fn process_tel_events_redb(
        post_data: String,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        process_tel_events(post_data, data).await
    }

    pub async fn resolve_location_redb(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        resolve_location(eid, data).await
    }

    pub async fn resolve_role_redb(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Arc<Witness<RedbOobiStorage>>>,
    ) -> Result<HttpResponse, ApiError> {
        resolve_role(path, data).await
    }
}
