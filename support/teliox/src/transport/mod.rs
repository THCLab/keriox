use keri::oobi::{LocationScheme, Scheme};

use crate::{error::Error, query::SignedTelQuery};

pub struct TelTransport;
impl TelTransport {
	pub async fn send_query(&self, qry: SignedTelQuery, location: LocationScheme) -> Result<String, Error> {
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
            .map_err(|_| Error::Generic("Transport error".to_string()))?;
        if !resp.status().is_success() {
            let body = resp
                .text()
                .await
            	.map_err(|_| Error::Generic("Transport error".to_string()))?;
			todo!()
            // let err = serde_json::from_str(&body).map_err(|_| Error::Generic("Transport error".to_string()))?;
            // err
        } else {
			resp
                .text()
                .await
            	.map_err(|_| Error::Generic("Transport error".to_string()))
		}
	}
}

pub enum HttpTransportError {
    NetworkError,
}
