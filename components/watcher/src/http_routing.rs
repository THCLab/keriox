use crate::watcher_listener::http_handlers;
use actix_web::web;

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.route(
        "/introduce",
        actix_web::web::get().to(http_handlers::introduce),
    )
    .route(
        "/oobi/{id}",
        actix_web::web::get().to(http_handlers::resolve_location),
    )
    .route(
        "/oobi/{cid}/{role}/{eid}",
        actix_web::web::get().to(http_handlers::resolve_role),
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
    .route(
        "/query/tel",
        actix_web::web::post().to(http_handlers::process_tel_query),
    )
    .route("info", actix_web::web::get().to(http_handlers::info));
}
