use crate::watcher_listener::http_handlers;
use actix_web::{web, HttpResponse};

async fn metrics_handler() -> HttpResponse {
    HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4; charset=utf-8")
        .body(crate::metrics::render())
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/metrics", actix_web::web::get().to(metrics_handler))
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
        "/register",
        actix_web::web::post().to(http_handlers::process_reply_redb),
    )
    .route(
        "/resolve",
        actix_web::web::post().to(http_handlers::resolve_oobi_redb),
    )
    .route(
        "/query/tel",
        actix_web::web::post().to(http_handlers::process_tel_query_redb),
    )
    .route("info", actix_web::web::get().to(http_handlers::info))
    .route(
        "/health",
        actix_web::web::get().to(http_handlers::health_redb),
    );
}
