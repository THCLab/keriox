use super::{HttpReq, HttpResp, HttpTransport, HttpTransportError};

struct DefaultHttpTransport;

#[async_trait::async_trait]
impl HttpTransport for DefaultHttpTransport {
    async fn send_http_request(&self, req: HttpReq) -> Result<HttpResp, HttpTransportError> {
        let client = reqwest::Client::new();
        let resp = match req {
            HttpReq::Get { url } => client.get(url).send().await,
            HttpReq::Post { url, body } => client.post(url).body(body).send().await,
        }
        .map_err(|_| HttpTransportError::NetworkError)?;

        let code = resp.status().as_u16();
        let body = resp
            .bytes()
            .await
            .map_err(|_| HttpTransportError::NetworkError)?;

        Ok(HttpResp { code, body })
    }
}
