use keri::{oobi::{LocationScheme, Scheme}};

use crate::{query::SignedTelQuery, event::verifiable_event::VerifiableEvent};

pub struct TelTransport;

#[async_trait::async_trait]
impl GeneralTelTransport for TelTransport {
	async fn send_query(&self, qry: SignedTelQuery, location: LocationScheme) -> Result<String, TransportError> {
		let url = match location.scheme {
            Scheme::Http => 
                    location.url.join("query/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
		let resp = reqwest::Client::new()
            .post(url)
            .body(qry.to_cesr().unwrap())
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if !resp.status().is_success() {
            let body = resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            	// .map_err(|_| Error::Generic("Transport error".to_string()))?;
			todo!()
            // let err = serde_json::from_str(&body).map_err(|_| Error::Generic("Transport error".to_string()))?;
            // err
        } else {
			resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
            Ok("ok".into())

		}
	}

    async fn send_tel_event(&self, qry: VerifiableEvent, location: LocationScheme) -> Result<String, TransportError> {
        let url = match location.scheme {
            Scheme::Http => 
                    location.url.join("process/tel").unwrap(),
            Scheme::Tcp => todo!(),
        };
        // todo!()
        let client = reqwest::Client::new();
        let query = qry.serialize().map_err(|e| TransportError::InvalidResponse)?;
		let resp = client//.get("http://witness1.sandbox.argo.colossi.network/introduce").send().await.unwrap();
            .post(url)
            .body(query)
            .send()
            .await
            .map_err(|_| TransportError::NetworkError)?;
        if !resp.status().is_success() {
            let body = resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
			todo!()
            // let err = serde_json::from_str(&body).map_err(|_| Error::Generic("Transport error".to_string()))?;
            // err
        } else {
			resp
                .text()
                .await
                .map_err(|_| TransportError::NetworkError)?;
		}
        Ok("Ok".into())
    }
}

pub enum HttpTransportError {
    NetworkError,
}

#[async_trait::async_trait]
pub trait GeneralTelTransport {
    async fn send_query(&self, qry: SignedTelQuery, location: LocationScheme) -> Result<String, TransportError>;
    async fn send_tel_event(&self, qry: VerifiableEvent, location: LocationScheme) -> Result<String, TransportError>;
}

#[derive(Debug, thiserror::Error, serde::Serialize, serde::Deserialize)]
pub enum TransportError {
    #[error("network error")]
    NetworkError,
    #[error("invalid response")]
    InvalidResponse,
}