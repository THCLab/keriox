use anyhow::{anyhow, Result};
use futures::AsyncReadExt;
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use async_std::{io::WriteExt, net::TcpStream};
use keri::{
    database::sled::SledEventDatabase,
    derivation::{self_addressing::SelfAddressing, self_signing::SelfSigning},
    event::{sections::threshold::SignatureThreshold, SerializationFormats},
    event_parsing::SignedEventData,
    keri::Keri,
    oobi::{EndRole, LocationScheme, OobiManager, Role, Scheme},
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, Prefix},
    query::reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    signer::{CryptoBox, KeyManager},
};

struct Controller {
    pub keri: Keri<CryptoBox>,
    oobi_manager: Arc<OobiManager>,
}
impl Controller {
    pub fn new(event_db_path: &Path, oobi_db_path: &Path) -> Self {
        let db = Arc::new(SledEventDatabase::new(event_db_path).unwrap());
        let alice_key_manager = { Arc::new(Mutex::new(CryptoBox::new().unwrap())) };

        let mut keri = Keri::new(Arc::clone(&db), alice_key_manager.clone()).unwrap();
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        keri.register_oobi_manager(oobi_manager.clone()).unwrap();
        Self {
            keri: keri,
            oobi_manager: oobi_manager.clone(),
        }
    }
    async fn resolve(&self, url: &str) -> Result<()> {
        let oobis = reqwest::get(url).await.unwrap().text().await.unwrap();
        println!("\ngot via http: {}", oobis);

        self.keri.parse_and_process(oobis.as_bytes()).unwrap();

        Ok(())
    }

    fn get_loc_schemas(&self, id: &IdentifierPrefix) -> Result<Vec<LocationScheme>> {
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

    async fn send_to(&self, wit_id: &IdentifierPrefix, schema: Scheme, msg: &[u8]) -> Result<()> {
        let addresses = self.get_loc_schemas(wit_id)?;
        match addresses
            .iter()
            .find(|loc| loc.scheme == schema)
            .map(|lc| &lc.url)
        {
            Some(address) => {
                let mut stream = TcpStream::connect(format!(
                    "{}:{}",
                    address
                        .host()
                        .ok_or(anyhow!("Wrong url, missing host {:?}", schema))?,
                    address
                        .port()
                        .ok_or(anyhow!("Wrong url, missing port {:?}", schema))?
                ))
                .await?;
                stream.write(&msg)
                .await?;
                println!("Sending message to witness {}", wit_id.to_str());
                let mut buf = vec![];
                let resp = stream.read(&mut buf);
                println!("Got response: {}", String::from_utf8(buf).unwrap());
                Ok(())
            }
            _ => Err(anyhow!("No address for scheme {:?}", schema)),
        }
    }

    fn generate_end_role(
        &self,
        watcher_id: &IdentifierPrefix,
        role: Role,
        enabled: bool,
    ) -> Result<SignedReply> {
        let end_role = EndRole {
            cid: self.keri.prefix().clone(),
            role,
            eid: watcher_id.clone(),
        };
        let reply_route = if enabled {
            ReplyRoute::EndRoleAdd(end_role)
        } else {
            ReplyRoute::EndRoleCut(end_role)
        };
        let reply = ReplyEvent::new_reply(
            reply_route,
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )
        .unwrap();
        let signature = self
            .keri
            .key_manager()
            .lock()
            .unwrap()
            .sign(&reply.serialize().unwrap())
            .unwrap();
        let att_signature = vec![AttachedSignaturePrefix::new(
            SelfSigning::Ed25519Sha512,
            signature,
            0,
        )];

        let signed_rpy = SignedReply::new_trans(
            reply,
            self.keri
                .storage
                .get_last_establishment_event_seal(self.keri.prefix())
                .unwrap()
                .unwrap(),
            att_signature,
        );
        Ok(signed_rpy)
    }

    async fn add_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<()> {
        let rep: SignedEventData = self
            .generate_end_role(watcher_id, Role::Watcher, true)?
            .into();
        self.send_to(watcher_id, Scheme::Tcp, &rep.to_cesr().unwrap())
            .await?;
        Ok(())
    }

    async fn remove_watcher(&self, watcher_id: &IdentifierPrefix) -> Result<()> {
        let rep: SignedEventData = self
            .generate_end_role(watcher_id, Role::Watcher, false)?
            .into();
        self.send_to(watcher_id, Scheme::Tcp, &rep.to_cesr().unwrap())
            .await?;
        Ok(())
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    use tempfile::Builder;

    let oobi_root = Builder::new().prefix("oobi-db").tempdir().unwrap();
    let event_db_root = Builder::new().prefix("test-db").tempdir().unwrap();
    let mut controller = Controller::new(event_db_root.path(), oobi_root.path());
    let witness_prefix: BasicPrefix = "BMOaOdnrbEP-MSQE_CaL7BhGXvqvIdoHEMYcOnUAWjOE"
        .parse()
        .unwrap();

    // Resolve oobi to know how to find witness
    controller
        .resolve(&format!(
            "http://localhost:3232/oobi/{}",
            witness_prefix.to_str()
        ))
        .await
        .unwrap();

    let loc_schemes = controller
        .get_loc_schemas(&IdentifierPrefix::Basic(witness_prefix.clone()))
        .unwrap();
    assert!(!loc_schemes.is_empty());

    controller
        .keri
        .incept(
            Some(vec![witness_prefix.clone()]),
            Some(SignatureThreshold::Simple(0)),
        )
        .unwrap();

    // send kel to witness to be able to verify end role message
    // TODO should watcher find kel by itself?
    let msg: Vec<_> = controller
        .keri
        .get_kel(controller.keri.prefix())
        .unwrap()
        .unwrap();

    controller
        .send_to(
            &IdentifierPrefix::Basic(witness_prefix.clone()),
            Scheme::Tcp,
            &msg,
        )
        .await
        .unwrap();

    controller
        .add_watcher(&IdentifierPrefix::Basic(witness_prefix))
        .await
        .unwrap();
    Ok(())
}
