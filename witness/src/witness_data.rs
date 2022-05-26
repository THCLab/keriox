use actix_web::{dev::Server, web, App, HttpServer};
use anyhow::Result;
use keri_actors::witness::Witness;
use std::{
    path::Path,
    sync::Arc,
};

use keri::{
    self,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    oobi::{LocationScheme, OobiManager},
    prefix::IdentifierPrefix,
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::Signer,
};

pub struct WitnessData {
    signer: Arc<Signer>,
    pub controller: Arc<Witness>,
    oobi_manager: Arc<OobiManager>,
}

impl WitnessData {
    pub fn setup(
        address: url::Url,
        public_address: Option<String>,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let signer = priv_key
            .map(|key| Signer::new_with_seed(&key.parse()?))
            .unwrap_or(Ok(Signer::new()))?;
        let mut witness = Witness::new(event_db_path, signer.public_key())?;
        // construct witness loc scheme oobi
        let pub_address = if let Some(pub_address) = public_address {
            url::Url::parse(&format!("http://{}", pub_address)).unwrap()
        } else {
            address.clone()
        };
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(witness.prefix.clone()),
            pub_address.scheme().parse().unwrap(),
            pub_address.clone(),
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
        Ok(WitnessData {
            controller: Arc::new(witness),
            oobi_manager,
            signer: Arc::new(signer),
        })
    }

    // TODO stop using url, use loc scheme oobi
    async fn resolve(&self, url: &str) -> Result<(), Error> {
        let oobis = reqwest::get(String::from_utf8(url.as_bytes().to_vec()).unwrap())
            .await
            .unwrap()
            .text()
            .await
            .unwrap();

        self.controller.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    pub fn listen_http(&self, address: url::Url) -> Server {
        use http_handlers::OobiResolving;
        let host = address.host().unwrap().to_string();
        let port = address.port().unwrap();

        let state = web::Data::new(OobiResolving::new(
            self.controller.prefix.clone(),
            self.oobi_manager.clone(),
            self.signer.clone(),
            self.controller.clone(),
        ));
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
}

pub mod tcp_handlers {
    use std::sync::Arc;

    use anyhow::Result;
    // use async_std::{
    //     io::{prelude::BufReadExt, BufReader, WriteExt},
    //     net::{TcpListener, TcpStream, ToSocketAddrs},
    //     prelude::StreamExt,
    //     task,
    // };
    use keri::{signer::Signer};
    use keri_actors::witness::Witness;

    pub struct KelUpdating {
        signer: Arc<Signer>,
        event_processor: Arc<Witness>,
    }

    impl KelUpdating {
        pub fn new(event_processor: Arc<Witness>, signer: Arc<Signer>) -> Self {
            Self {
                event_processor,
                signer,
            }
        }

        pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<()> {
            self.event_processor
                .parse_and_process(input_stream)
                .unwrap();
            Ok(())
        }
    }

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
}

pub mod http_handlers {
    use anyhow::Result;
    use keri_actors::witness::Witness;
    use std::sync::Arc;

    use actix_web::{get, http::header::ContentType, post, web, HttpResponse, Responder};
    use keri::{
        derivation::self_signing::SelfSigning,
        event_parsing::SignedEventData,
        oobi::{OobiManager, Role},
        prefix::{BasicPrefix, IdentifierPrefix, Prefix},
        query::reply_event::SignedReply,
        signer::Signer,
    };

    pub struct OobiResolving {
        prefix: BasicPrefix,
        oobi_manager: Arc<OobiManager>,
        signer: Arc<Signer>,
        event_processor: Arc<Witness>,
    }

    impl OobiResolving {
        pub fn new(
            prefix: BasicPrefix,
            oobi_manager: Arc<OobiManager>,
            signer: Arc<Signer>,
            event_processor: Arc<Witness>,
        ) -> Self {
            Self {
                prefix,
                oobi_manager,
                signer,
                event_processor,
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
                                self.prefix.clone(),
                                SelfSigning::Ed25519Sha512.derive(signature),
                            )
                        })
                        .collect(),
                ),
                None => None,
            })
        }

        pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<()> {
            self.event_processor
                .parse_and_process(input_stream)
                .unwrap();
            Ok(())
        }
    }

    #[get("/oobi/{id}")]
    pub async fn get_eid_oobi(
        eid: web::Path<IdentifierPrefix>,
        data: web::Data<OobiResolving>,
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
        data: web::Data<OobiResolving>,
    ) -> impl Responder {
        let (cid, role, eid) = path.into_inner();

        let end_role = data.get_cid_end_role(&cid, role).unwrap().unwrap_or(vec![]);
        let loc_scheme = data.get_eid_loc_scheme(&eid).unwrap().unwrap_or(vec![]);
        // (for now) Append controller kel to be able to verify end role signature.
        // TODO use ksn instead
        let cont_kel = data
            .event_processor
            .get_kel_for_prefix(&cid)
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
    pub async fn process_stream(post_data: String, data: web::Data<OobiResolving>) -> impl Responder {
        println!("\nGot events to process: \n{}", post_data);
        data.parse_and_process(post_data.as_bytes()).unwrap();
        let resp = data
            .event_processor
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
}



