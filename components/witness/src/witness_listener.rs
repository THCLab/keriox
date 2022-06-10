use actix_web::{dev::Server, web, App, HttpServer};
use anyhow::Result;
use std::{path::Path, sync::Arc};

use keri::{self, error::Error, prefix::BasicPrefix};

use crate::witness::Witness;

pub struct WitnessListener {
    witness_data: Arc<Witness>,
}

impl WitnessListener {
    pub fn setup(
        address: url::Url,
        public_address: Option<String>,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let pub_address = if let Some(pub_address) = public_address {
            url::Url::parse(&format!("http://{}", pub_address)).unwrap()
        } else {
            address.clone()
        };

        Witness::setup(pub_address, event_db_path, oobi_db_path, priv_key).map(|wd| Self {
            witness_data: Arc::new(wd),
        })
    }

    pub fn listen_http(&self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(self.witness_data.clone());
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(http_handlers::get_eid_oobi)
                .service(http_handlers::get_cid_oobi)
                .service(http_handlers::process_stream)
            // .service(resolve)
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.witness_data.prefix.clone()
    }
}

pub mod http_handlers {
    use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};
    use keri::{
        event_parsing::SignedEventData,
        oobi::Role,
        prefix::{IdentifierPrefix, Prefix},
    };

    use crate::witness::Witness;

    #[get("/oobi/{id}")]
    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Witness>,
    ) -> impl Responder {
        let loc_scheme = data.get_loc_scheme_for_id(&eid).unwrap().unwrap_or(vec![]);
        let oobis: Vec<u8> = loc_scheme
            .into_iter()
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten()
            .collect();

        println!(
            "\nSending {} oobi: \n {}",
            &eid.to_str(),
            String::from_utf8(oobis.clone()).unwrap_or_default()
        );
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap())
    }

    #[get("/oobi/{cid}/{role}/{eid}")]
    pub async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<Witness>,
    ) -> impl Responder {
        let (cid, role, eid) = path.into_inner();

        let end_role = data
            .oobi_manager
            .get_end_role(&cid, role)
            .unwrap()
            .unwrap_or(vec![]);
        let loc_scheme = data.get_loc_scheme_for_id(&eid).unwrap().unwrap_or(vec![]);
        // (for now) Append controller kel to be able to verify end role signature.
        // TODO use ksn instead
        let cont_kel = data
            .event_storage
            .get_kel(&cid)
            .unwrap()
            .unwrap_or_default();
        let oobis = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten();
        let res: Vec<u8> = cont_kel.into_iter().chain(oobis).collect();
        println!(
            "\nSending {} obi from its witness {}:\n{}",
            cid.to_str(),
            eid.to_str(),
            String::from_utf8(res.clone()).unwrap()
        );

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(res).unwrap())
    }

    #[post("/process")]
    pub async fn process_stream(post_data: String, data: web::Data<Witness>) -> impl Responder {
        println!("\nGot events to process: \n{}", post_data);
        let resp = data
            .parse_and_process(post_data.as_bytes())
            .unwrap()
            .iter()
            .map(|msg| msg.to_cesr().unwrap())
            .flatten()
            .collect();
        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(resp).unwrap())
    }
}
