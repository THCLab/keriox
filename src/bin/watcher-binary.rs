use actix_web::{dev::Server, web, App, HttpServer};
use anyhow::Result;
use figment::{
    providers::{Format, Json},
    Figment,
};
use futures::future::join_all;
use serde::Deserialize;
use std::{
    path::{Path, PathBuf},
    sync::Arc, convert::TryFrom,
};
use structopt::StructOpt;

use keri::{
    self,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    keri::witness::Witness,
    oobi::{LocationScheme, OobiManager, Role, Scheme, EndRole},
    prefix::{IdentifierPrefix, Prefix},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::Signer, event_parsing::message::signed_event_stream, event_message::signed_event_message::Message,
};

struct WatcherData {
    http_address: url::Url,
    signer: Arc<Signer>,
    pub controller: Arc<Witness>,
    oobi_manager: Arc<OobiManager>,
}

impl WatcherData {
    pub fn setup(
        address: url::Url,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let signer = priv_key
            .map(|key| Signer::new_with_key(&key))
            .unwrap_or(Ok(Signer::new()))?;
        let mut witness = Witness::new(event_db_path, signer.public_key())?;
        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(witness.prefix.clone()),
            address.scheme().parse().unwrap(),
            address.clone(),
        );
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            SelfAddressing::Blake3_256,
            keri::event::SerializationFormats::JSON,
        )?;
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            witness.prefix.clone(),
            SelfSigning::Ed25519Sha512.derive(signer.sign(reply.serialize()?)?),
        );
        oobi_manager.save_oobi(signed_reply)?;
        witness.register_oobi_manager(oobi_manager.clone());
        Ok(WatcherData {
            http_address: address,
            controller: Arc::new(witness),
            oobi_manager,
            signer: Arc::new(signer),
        })
    }

     pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<()> {
            self.controller
                .parse_and_process(input_stream)
                .unwrap();
            Ok(())
        }
    
    pub async fn resolve(&self, lc: LocationScheme) -> Result<()> {
        let url = format!("{}oobi/{}", lc.url, lc.eid);
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();
        println!("\ngot via http: {}", oobis);

        self.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

     pub async fn resolve_end_role(&self, lc: EndRole) -> Result<()> {

        let url = match self.get_eid_loc_scheme(&lc.eid.clone())?.unwrap()[0].reply.event.content.data.clone() {
            ReplyRoute::Ksn(_, _) => todo!(),
            ReplyRoute::LocScheme(lc) => lc.url,
            ReplyRoute::EndRoleAdd(_) => todo!(),
            ReplyRoute::EndRoleCut(_) => todo!(),
        };
        let url = format!("{}oobi/{}/{}/{}", url, lc.cid, "witness", lc.eid);
        println!("\n\n url: {}", url);
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();
        println!("\ngot via http: {}", oobis);

        self.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

        // pub fn parse_and_process_query(&self, input_stream: Vec<u8>) -> Result<String> {
        //     let events = signed_event_stream(input_stream.clone())?.1;

        //     let output = events
        //         .into_iter()
        //         .map(|event| {
        //             // for event in events {
        //             let msg = Message::try_from(event).unwrap();
        //             if let Message::Query(qr) = msg {
        //                 let output = match self.controller
        //                     .process_signed_query(qr, self.signer.clone())
        //                     .unwrap()
        //                 {
        //                     keri::query::ReplyType::Rep(rep) => {
        //                         Message::Reply(rep).to_cesr().unwrap()
        //                     }
        //                     keri::query::ReplyType::Kel(kel) => kel,
        //                 };
        //                 output
        //             } else {
        //                 // TODO Wrong event type, ignore or return error?
        //                 "".into()
        //             }
        //         })
        //         .flatten()
        //         .collect();
        //     Ok(String::from_utf8(output).unwrap())
        // }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
        use anyhow::anyhow;
        Ok(self
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
        use anyhow::anyhow;
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
                    // let mut stream = TcpStream::connect(format!(
                    //     "{}:{}",
                    //     address
                    //         .host()
                    //         .ok_or(anyhow!("Wrong url, missing host {:?}", schema))?,
                    //     address
                    //         .port()
                    //         .ok_or(anyhow!("Wrong url, missing port {:?}", schema))?
                    // ))
                    // .await?;
                    // stream.write(&msg).await?;
                    // println!("Sending message to witness {}", wit_id.to_str());
                    // let mut buf = vec![];
                    // stream.read(&mut buf).await?;
                    // println!("Got response: {}", String::from_utf8(buf).unwrap());
                    // Ok(None)
                    todo!()
                }
            },
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }

    fn get_cid_end_role(
            &self,
            cid: &IdentifierPrefix,
            role: Role,
        ) -> Result<Option<Vec<SignedReply>>> {
            Ok(self.oobi_manager.get_end_role(cid, role).unwrap())
        }

        fn get_eid_loc_scheme(&self, eid: &IdentifierPrefix) -> Result<Option<Vec<SignedReply>>> {
            Ok(match self.oobi_manager.get_loc_scheme(eid).unwrap() {
                Some(oobis_to_sign) => Some(
                    oobis_to_sign
                        .iter()
                        .map(|oobi_to_sing| {
                            let signature =
                                self.signer.sign(oobi_to_sing.serialize().unwrap()).unwrap();
                            SignedReply::new_nontrans(
                                oobi_to_sing.clone(),
                                self.controller.prefix.clone(),
                                SelfSigning::Ed25519Sha512.derive(signature),
                            )
                        })
                        .collect(),
                ),
                None => None,
            })
        }

    fn listen_http(self, address: url::Url) -> Server {
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(self);
        HttpServer::new(move || {
            App::new()
                .app_data(state.clone())
                .service(oobi_http_handlers::get_eid_oobi)
                .service(oobi_http_handlers::get_cid_oobi)
                .service(kel_http_handlers::get_kel)
            // .service(resolve)
        })
        .bind((host, port))
        .unwrap()
        .run()
    }
}

pub mod kel_http_handlers {
    use std::convert::TryFrom;

    use actix_web::{http::header::ContentType, post, web, HttpResponse, Responder, get};
    use keri::{
        prefix::{IdentifierPrefix, AttachedSignaturePrefix}, query::{query_event::{QueryEvent, QueryArgs, SignedQuery}, QueryRoute}, derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning}, oobi::Role, event_parsing::SignedEventData, event_message::signed_event_message::Message,
    };

    use crate::WatcherData;

    // pub async fn accept_loop(data: Arc<KelUpdating>, addr: impl ToSocketAddrs) -> Result<()> {
    //     let listener = TcpListener::bind(addr).await?;
    //     let mut incoming = listener.incoming();
    //     while let Some(stream) = incoming.next().await {
    //         let stream = stream?;
    //         println!("Accepting from: {}", stream.peer_addr()?);
    //         let _handle = task::spawn(handle_connection(stream, data.clone()));
    //     }
    //     Ok(())
    // }

    // async fn handle_connection(stream: TcpStream, data: Arc<KelUpdating>) -> Result<()> {
    //     let reader = BufReader::new(&stream);
    //     let mut lines = reader.lines();

    //     while let Some(line) = lines.next().await {
    //         println!("\ngot via tcp: {}\n", line.as_deref().unwrap());
    //         data.parse_and_process(line.unwrap().as_bytes()).unwrap();
    //     }
    //     let resp = data
    //         .event_processor
    //         .respond(data.signer.clone())
    //         .unwrap()
    //         .iter()
    //         .map(|msg| msg.to_cesr().unwrap())
    //         .flatten()
    //         .collect::<Vec<_>>();
    //     stream.clone().write_all(&resp).await?;

    //     Ok(())
    // }

    #[post("/process")]
    async fn process_stream(body: web::Bytes, data: web::Data<WatcherData>) -> impl Responder {
        data.parse_and_process(&body).unwrap();
        let resp = data
            .controller
            .clone()
            .respond(data.signer.clone())
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
        data: web::Data<WatcherData>,
    ) -> impl Responder {
        // generate query message here
        let id = eid.clone();
        let qr = QueryArgs { s: None, i: id.clone(), src: None };
        let qry_message = QueryEvent::new_query(
            QueryRoute::Log, 
            qr, 
            keri::event::SerializationFormats::JSON,
            &SelfAddressing::Blake3_256
        ).unwrap();
        let signature = data.signer.sign(qry_message.serialize().unwrap()).unwrap();
        let signatures =  vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                signature,
                0,
            )];
        let signed_qry = SignedQuery::new(qry_message, keri::prefix::IdentifierPrefix::Basic(data.controller.prefix.clone()), signatures);
        let cid = &data.get_cid_end_role(&id, Role::Witness).unwrap().unwrap()[0].reply.event.content.data;


        let witness_id = match cid {
            keri::query::reply_event::ReplyRoute::Ksn(_, _) => todo!(),
            keri::query::reply_event::ReplyRoute::LocScheme(_) => todo!(),
            keri::query::reply_event::ReplyRoute::EndRoleAdd(endrole) => endrole.eid.clone(),
            keri::query::reply_event::ReplyRoute::EndRoleCut(_) => todo!(),
        };
        // get witness adress and send there query
        let qry_str = Message::Query(signed_qry).to_cesr().unwrap();
        println!("sending query: {}", String::from_utf8(qry_str.clone()).unwrap());
        let resp = data.send_to(witness_id, keri::oobi::Scheme::Http, qry_str).await.unwrap().unwrap();

        HttpResponse::Ok()
            .content_type(ContentType::plaintext())
            .body(resp)
    }
}

pub mod oobi_http_handlers {
    use actix_web::{get, http::header::ContentType, web, HttpResponse, Responder};
    use keri::{
        event_parsing::SignedEventData,
        oobi::Role,
        prefix::{IdentifierPrefix, Prefix},
    };

    use crate::WatcherData;

    #[get("/oobi/{id}")]
    async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<WatcherData>,
    ) -> impl Responder {
        let loc_scheme = data.get_eid_loc_scheme(&eid).unwrap().unwrap_or(vec![]);
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
        println!("cid: {}, eid: {}\n", cid.to_str(), eid.to_str());

        let end_role = data.get_cid_end_role(&cid, role).unwrap().unwrap_or(vec![]);
        let loc_scheme = data.get_eid_loc_scheme(&eid).unwrap().unwrap_or(vec![]);
        let oobis: Vec<u8> = end_role
            .into_iter()
            .chain(loc_scheme.into_iter())
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
}

#[derive(Deserialize)]
pub struct WitnessConfig {
    // witness_db_path: PathBuf,
    // oobis_db_path: PathBuf,
    /// Witness listen host.
    http_host: String,
    /// Witness listen port.
    http_port: u16,
    /// Witness listen host.
    tcp_host: String,
    /// Witness listen port.
    tcp_port: u16,
    /// Witness private key
    priv_key: Option<Vec<u8>>,
}

#[derive(Debug, StructOpt)]
struct Opts {
    #[structopt(short = "c", long, default_value = "./src/bin/configs/watcher.json")]
    config_file: String,
}

#[actix_web::main]
async fn main() -> Result<()> {
    let Opts { config_file } = Opts::from_args();

    let WitnessConfig {
        // witness_db_path,
        // oobis_db_path,
        http_host,
        http_port,
        tcp_host,
        tcp_port,
        priv_key,
    } = Figment::new().join(Json::file(config_file)).extract()?;

    use tempfile::Builder;
    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let event_db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let tcp_address = format!("tcp://{}:{}", tcp_host, tcp_port);
    let http_address = format!("http://{}:{}", http_host, http_port);

    let wit_data = WatcherData::setup(
        url::Url::parse(&http_address).unwrap(),
        event_db_root.path(),
        oobi_root.path(),
        priv_key,
    )
    .unwrap();
    let wit_prefix = wit_data.controller.prefix.clone();
    // let wit_ref = Arc::new(wit_data);
    // let wit_ref2 = wit_ref.clone();


    // resolve witnesses oobis
    let witness_prefixes = vec![
        "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE",
        "BZFIYlHDQAHxHH3TJsjMhZFbVR_knDzSc3na_VHBZSBs",
        "BYSUc5ahFNbTaqesfY-6YJwzALaXSx-_Mvbs6y3I74js",
    ]
    .iter()
    .map(|prefix_str| prefix_str.parse::<IdentifierPrefix>().unwrap())
    .collect::<Vec<_>>();

    let witness_addresses = vec![
        "http://localhost:3232",
        "http://localhost:3234",
        "http://localhost:3235",
    ];

    // Resolve oobi to know how to find witness
    join_all(
        witness_prefixes
            .iter()
            .zip(witness_addresses.iter())
            .map(|(prefix, address)| {
                let lc = LocationScheme::new(prefix.clone(), Scheme::Http, url::Url::parse(address).unwrap());
                wit_data.resolve(lc)
            }),
    )
    .await;

    let issuer_id = "EMI1a7MCfDG_BwE4kGTt5K7fmF3pbKHKy4xE-Ajb1u_Y";
    // resolve issuer oobi
    wit_data
        .resolve_end_role(EndRole { 
            cid: issuer_id.parse().unwrap(), 
            role: Role::Witness, 
            eid: "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE".parse().unwrap() 
        }).await.unwrap();


    println!(
        "Watcher {} is listening. \n\toobis: {} \n\tevents: {}",
        wit_prefix.to_str(),
        http_address,
        tcp_address
    );
    // run http server for oobi resolving
    let http_handle = wit_data.listen_http(url::Url::parse(&http_address).unwrap());
    // run tcp server for getting events
    // let tcp_handle = wit_ref2.listen_tcp();
    // future::join(http_handle, tcp_handle).await;
    http_handle.await;

    Ok(())
}