//! Counts requests by the keriox release of their client and, when the
//! node requires a minimum release, refuses clients older than that.

use actix_web::{
    body::MessageBody,
    dev::{ServiceRequest, ServiceResponse},
    http::{header, Method},
    middleware::Next,
    HttpResponse,
};
use keri_core::transport::client_version::{is_too_old, Version};

/// Middleware for the public listener. A request that sends messages to
/// the node (`POST`) from a client older than `minimum` gets
/// `426 Upgrade Required`; `GET` requests (`/info`, OOBIs, introductions)
/// stay open to any client.
pub async fn client_gate<B: MessageBody + 'static>(
    minimum: Option<Version>,
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let agent = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|agent| agent.to_str().ok())
        .map(str::to_owned);
    crate::metrics::count_client(agent.as_deref());
    if let Some(minimum) = minimum {
        if req.method() == Method::POST && is_too_old(agent.as_deref(), &minimum) {
            let response = HttpResponse::UpgradeRequired().json(serde_json::json!({
                "error": "client_too_old",
                "min_client_version": minimum.to_string(),
            }));
            return Ok(req.into_response(response).map_into_right_body());
        }
    }
    next.call(req).await.map(ServiceResponse::map_into_left_body)
}

#[cfg(test)]
mod tests {
    use actix_web::{
        http::{header, StatusCode},
        middleware::from_fn,
        test, web, App, HttpResponse,
    };
    use keri_core::transport::client_version::Version;

    use super::client_gate;

    async fn status(minimum: Option<&str>, method: &str, agent: Option<&str>) -> StatusCode {
        let minimum = minimum.map(|minimum| Version::parse(minimum).unwrap());
        let app = test::init_service(
            App::new()
                .wrap(from_fn(move |req, next| client_gate(minimum.clone(), req, next)))
                .route("/process", web::post().to(HttpResponse::Ok))
                .route("/info", web::get().to(HttpResponse::Ok)),
        )
        .await;
        let mut req = match method {
            "POST" => test::TestRequest::post().uri("/process"),
            _ => test::TestRequest::get().uri("/info"),
        };
        if let Some(agent) = agent {
            req = req.insert_header((header::USER_AGENT, agent));
        }
        test::call_service(&app, req.to_request()).await.status()
    }

    #[actix_web::test]
    async fn without_a_minimum_every_client_is_served() {
        assert_eq!(status(None, "POST", None).await, StatusCode::OK);
        assert_eq!(
            status(None, "POST", Some("keriox/0.19.0")).await,
            StatusCode::OK
        );
    }

    #[actix_web::test]
    async fn an_older_client_is_told_to_upgrade() {
        let minimum = Some("0.20.0");
        assert_eq!(
            status(minimum, "POST", Some("keriox/0.19.0-rc.6")).await,
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(
            status(minimum, "POST", None).await,
            StatusCode::UPGRADE_REQUIRED
        );
        assert_eq!(
            status(minimum, "POST", Some("keriox/0.20.0")).await,
            StatusCode::OK
        );
        // Discovery stays open.
        assert_eq!(status(minimum, "GET", None).await, StatusCode::OK);
    }
}
