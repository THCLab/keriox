use actix_web::{dev::Server, web, App, HttpServer};
use anyhow::{anyhow, Result};
use futures::future::join_all;
use std::path::Path;

use keri::{
    component::NontransferableActor,
    error::Error,
    oobi::{EndRole, LocationScheme, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::BasicProcessor,
    query::reply_event::ReplyRoute,
};

pub type WatcherData = NontransferableActor<BasicProcessor>;

pub struct WatcherListener {
    watcher_data: Communication,
}

impl WatcherListener {
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

        WatcherData::setup(pub_address, event_db_path, oobi_db_path, priv_key).map(|watcher_data| {
            Self {
                watcher_data: Communication(watcher_data),
            }
        })
    }

    pub fn listen_http(self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(self.watcher_data);
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(http_handlers::get_eid_oobi)
                .service(http_handlers::get_cid_oobi)
                .service(http_handlers::get_kel)
                .service(http_handlers::resolve_oobi)
                .service(http_handlers::process_stream)
            // .service(resolve)
        })
        .bind((host, port))
        .unwrap()
        .run()
    }

    pub async fn resolve_initial_oobis(
        &self,
        initial_oobis: &[LocationScheme],
    ) -> Result<(), Error> {
        join_all(
            initial_oobis
                .iter()
                .map(|lc| self.watcher_data.resolve_loc_scheme(lc)),
        )
        .await;
        Ok(())
    }

    pub fn get_prefix(&self) -> BasicPrefix {
        self.watcher_data.0.prefix.clone()
    }
}

pub struct Communication(WatcherData);

impl Communication {
    pub async fn resolve_end_role(&self, er: EndRole) -> Result<()> {
        // find endpoint data of endpoint provider identifier
        let loc_scheme = self
            .0
            .get_loc_scheme_for_id(&er.eid.clone())
            .unwrap()
            .unwrap()[0]
            .reply
            .event
            .content
            .data
            .clone();

        if let ReplyRoute::LocScheme(lc) = loc_scheme {
            let url = format!("{}oobi/{}/{}/{}", lc.url, er.cid, "witness", er.eid);
            let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();

            self.0.parse_and_process(oobis.as_bytes()).unwrap();
            Ok(())
        } else {
            Err(anyhow!("Wrong oobi type"))
        }
    }

    pub async fn resolve_loc_scheme(&self, lc: &LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();

        self.0.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        Ok(self
            .0
            .oobi_manager
            .get_loc_scheme(id)
            .unwrap()
            .unwrap()
            .iter()
            .filter_map(|lc| {
                if let ReplyRoute::LocScheme(loc_scheme) = lc.get_route() {
                    Ok(loc_scheme)
                } else {
                    Err(anyhow!("Wrong route type"))
                }
                .ok()
            })
            .collect())
    }

    async fn send_to(
        &self,
        wit_id: IdentifierPrefix,
        schema: Scheme,
        msg: Vec<u8>,
    ) -> Result<Option<String>> {
        let addresses = self.get_loc_schemas(&wit_id)?;
        match addresses
            .iter()
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => match schema {
                Scheme::Http => {
                    let client = reqwest::Client::new();
                    let response = client
                        .post(format!("{}process", address))
                        .body(msg)
                        .send()
                        .await?
                        .text()
                        .await?;

                    println!("\ngot response: {}", response);
                    Ok(Some(response))
                }
                Scheme::Tcp => {
                    todo!()
                }
            },
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }
}

pub mod http_handlers {

    use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};
    use keri::{
        derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
        event_message::signed_event_message::Message,
        event_parsing::SignedEventData,
        oobi::{EndRole, LocationScheme, Role},
        prefix::{AttachedSignaturePrefix, IdentifierPrefix, Prefix},
        query::query_event::{QueryArgs, QueryEvent, QueryRoute, SignedQuery},
    };

    use super::{Communication, WatcherData};

    #[post("/process")]
    async fn process_stream(body: web::Bytes, data: web::Data<Communication>) -> impl Responder {
        println!(
            "\nGot events to process: \n{}",
            String::from_utf8(body.to_vec()).unwrap()
        );
        let resp = data
            .0
            .parse_and_process(&body)
            .unwrap()
            .iter()
            .map(|msg| msg.to_cesr().unwrap())
            .flatten()
            .collect::<Vec<_>>();

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(resp).unwrap())
    }

    #[get("/query/{id}")]
    async fn get_kel(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<Communication>,
    ) -> impl Responder {
        // generate query message here
        let id = eid.clone();
        let qr = QueryArgs {
            s: None,
            i: id.clone(),
            src: None,
        };
        let qry_message = QueryEvent::new_query(
            QueryRoute::Log {
                args: qr,
                reply_route: String::from(""),
            },
            keri::event::SerializationFormats::JSON,
            &SelfAddressing::Blake3_256,
        )
        .unwrap();
        let signature = data
            .0
            .signer
            .sign(qry_message.serialize().unwrap())
            .unwrap();
        let signatures = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];
        let signed_qry = SignedQuery::new(
            qry_message,
            keri::prefix::IdentifierPrefix::Basic(data.0.prefix.clone()),
            signatures,
        );

        // Get witnesses, and TODO choose one randomly.
        let witnesses = data
            .0
            .actor
            .get_state_for_prefix(&id)
            .unwrap()
            .unwrap()
            .witness_config
            .witnesses;
        let witness_id = IdentifierPrefix::Basic(witnesses[0].clone());

        // get witness address and send there query
        let qry_str = Message::Query(signed_qry).to_cesr().unwrap();
        println!(
            "\nSending query to {}: \n{}",
            witness_id.to_str(),
            String::from_utf8(qry_str.clone()).unwrap()
        );
        let resp = data
            .send_to(witness_id, keri::oobi::Scheme::Http, qry_str)
            .await
            .unwrap()
            .unwrap();

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp)
    }

    #[post("/resolve")]
    async fn resolve_oobi(body: web::Bytes, data: web::Data<Communication>) -> impl Responder {
        println!(
            "\nGot oobi to resolve: \n{}",
            String::from_utf8(body.to_vec()).unwrap()
        );

        match serde_json::from_str::<EndRole>(&String::from_utf8(body.to_vec()).unwrap()) {
            Ok(end_role) => data.resolve_end_role(end_role).await.unwrap(),
            Err(_) => {
                let lc = serde_json::from_str::<LocationScheme>(
                    &String::from_utf8(body.to_vec()).unwrap(),
                )
                .unwrap();
                data.resolve_loc_scheme(&lc).await.unwrap()
            }
        };

        HttpResponse::Ok()
    }

    #[get("/oobi/{id}")]
    async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<WatcherData>,
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

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap())
    }

    #[get("/oobi/{cid}/{role}/{eid}")]
    async fn get_cid_oobi(
        path: web::Path<(IdentifierPrefix, Role, IdentifierPrefix)>,
        data: web::Data<WatcherData>,
    ) -> impl Responder {
        let (cid, role, eid) = path.into_inner();

        let end_role = data
            .get_end_role_for_id(&cid, role)
            .unwrap()
            .unwrap_or(vec![]);
        let loc_scheme = data.get_loc_scheme_for_id(&eid).unwrap().unwrap_or(vec![]);
        let oobis: Vec<u8> = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
            .map(|sr| {
                let sed: SignedEventData = sr.into();
                sed.to_cesr().unwrap()
            })
            .flatten()
            .collect();
        println!(
            "\nSending {} obi from its watcher {}:\n{}",
            cid.to_str(),
            eid.to_str(),
            String::from_utf8(oobis.clone()).unwrap()
        );

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(String::from_utf8(oobis).unwrap())
    }
}
