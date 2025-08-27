use ed25519_dalek::SigningKey;
use keri_core::{
    actor::parse_event_stream,
    event_message::{
        signature::{Nontransferable, Signature},
        signed_event_message::{Message, Op},
    },
    prefix::{BasicPrefix, IdentifierPrefix, SeedPrefix, SelfSigningPrefix},
    query::query_event::{SignedKelQuery, SignedQueryMessage},
    signer::Signer,
};
use keri_sdk::{database::redb::RedbDatabase, Controller};
use std::sync::Arc;
use teliox::database::{redb::RedbTelDatabase, TelEventDatabase};

struct KeysConfig {
    pub current: SeedPrefix,
    pub next: SeedPrefix,
}

impl Default for KeysConfig {
    fn default() -> Self {
        let current = SigningKey::generate(&mut rand::rngs::OsRng);
        let next = SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            current: SeedPrefix::RandomSeed256Ed25519(
                current.as_bytes().to_vec(),
            ),
            next: SeedPrefix::RandomSeed256Ed25519(next.as_bytes().to_vec()),
        }
    }
}

#[tokio::test]
async fn test_init_id() -> Result<(), ()> {
    let root = tempfile::Builder::new()
        .prefix("test-db")
        .tempdir()
        .unwrap();
    println!("Root path: {:?}", root.path());
    std::fs::create_dir_all(root.path()).unwrap();

    let db_path = root.path().to_path_buf();
    let event_database = {
        let mut path = db_path.clone();
        path.push("events_database");
        Arc::new(RedbDatabase::new(&path).unwrap())
    };

    let tel_events_db = {
        let mut path = db_path.clone();
        path.push("tel");
        path.push("events");
        Arc::new(RedbTelDatabase::new(&path).unwrap())
    };

    let keys = KeysConfig::default();
    let (next_pub_key, _next_secret_keys) =
        keys.next.derive_key_pair().map_err(|_e| ())?;

    let signer =
        Arc::new(Signer::new_with_seed(&keys.current.clone()).unwrap());

    let controller = Controller::new(event_database, tel_events_db);
    let public_keys = vec![BasicPrefix::Ed25519(signer.public_key())];
    let next_pub_keys = vec![BasicPrefix::Ed25519NT(next_pub_key)];

    let signing_inception =
        controller.incept(public_keys.clone(), next_pub_keys)?;
    let signature = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign(signing_inception.as_bytes()).unwrap(),
    );
    let signing_identifier =
        controller.finalize_incept(signing_inception.as_bytes(), &signature)?;
    println!("Identifier: {:?}", signing_identifier.get_prefix());
    println!("KEL: {:?}", signing_identifier.get_own_kel());

    let witness_id = serde_json::Value::String(
        "BNJJhjUnhlw-lsbYdehzLsX1hJMG9QJlK_wJ5AunJLrM".to_string(),
    );
    let id_str = serde_json::Value::String(
        "EHIydjfGpSu8mKvrDeWWPaV-mBPeP6Ad7DE6v5fZv2ps".to_string(),
    );
    let id: IdentifierPrefix =
        serde_json::from_value(id_str).map_err(|_e| ())?;
    let witness_prefix: IdentifierPrefix =
        serde_json::from_value(witness_id).map_err(|_e| ())?;
    let q = signing_identifier.get_log_query(id, witness_prefix);
    let signature_qry = Signature::NonTransferable(Nontransferable::Couplet(vec![(
            public_keys[0].clone(),
            SelfSigningPrefix::new(
                cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
                signer.sign(q.encode().unwrap()).unwrap(),
            )
    )]));
    let singed_kel_q = SignedKelQuery {
        query: q,
        signature: signature_qry,
    };
    let signed_qry = SignedQueryMessage::KelQuery(singed_kel_q);

    let body = Message::Op(Op::Query(signed_qry)).to_cesr().unwrap();
    let client = reqwest::Client::new();
    let url: url::Url = serde_json::from_value(serde_json::Value::String(
        "http://w1.ea.argo.colossi.network/query".to_string(),
    ))
    .map_err(|_e| ())?;
    let response = client.post(url).body(body).send().await.map_err(|e| {
        eprintln!("Request error: {:?}", e);
    })?;

    if !response.status().is_success() {
        println!("Request failed with status: {}", response.status());
        let error_text = response.text().await.map_err(|_| ())?;
        println!("Error body: {}", error_text);
        return Err(());
    }

    let kel = response.text().await.map_err(|_| ())?;
    let parsed_kel = parse_event_stream(kel.as_bytes()).map_err(|_e| ())?;
    println!("KEL: {:?}", kel);
    println!("Parsed KEL: {:?}", parsed_kel.len());
    controller.process_kel(&parsed_kel).map_err(|e| {
        eprintln!("Processing error: {:?}", e);
    })?;

    // let msg = r#"{"v":"ACDC10JSON000207_","d":"EGRIIeNj2HIP787COJFiQbYqsp6UwAR22oeqWsEVhq42","i":"EHIydjfGpSu8mKvrDeWWPaV-mBPeP6Ad7DE6v5fZv2ps","ri":"EMDfCDynqGvpaN7Fbm5FADyfS98q_WUkPKmbZapBB1J_","s":"EHLjK9n1i1osh8SPYpyotPxC8IeBqtdfK-Qrz4_TZp6G","a":{"d":"ENaVuh9EMbTGgVjbnPHDZDDxvhsvzIZsuvTEIkFa3JPP","a":{"last_name":"KOWALSKI","first_name":"JAN","birth_date":"07.04.1964","birth_place":"WARSZAWA","issue_date":"06.03.2019","expiry_date":"18.01.2028","issuer":"PREZYDENT m.st. WARSZAWY","pesel":"64040738293","number":"SP006/15/1"}}}"#;
    let vc_said: said::SelfAddressingIdentifier =
        "EGRIIeNj2HIP787COJFiQbYqsp6UwAR22oeqWsEVhq42"
            .parse()
            .unwrap();
    let registry_id: said::SelfAddressingIdentifier =
        "EMDfCDynqGvpaN7Fbm5FADyfS98q_WUkPKmbZapBB1J_"
            .parse()
            .unwrap();

    let tel_qry = signing_identifier
        .get_tel_query(
            IdentifierPrefix::self_addressing(registry_id),
            IdentifierPrefix::self_addressing(vc_said.clone()),
        )
        .map_err(|_e| ())?;

    let signature_tel_query = SelfSigningPrefix::new(
        cesrox::primitives::codes::self_signing::SelfSigning::Ed25519Sha512,
        signer.sign(tel_qry.encode().unwrap()).unwrap(),
    );
    let tel_query = match signing_identifier.id {
        IdentifierPrefix::Basic(bp) => {
            teliox::query::SignedTelQuery::new_nontrans(
                tel_qry.clone(),
                bp.clone(),
                signature_tel_query,
            )
        }
        _ => {
            let signatures =
                vec![keri_core::prefix::IndexedSignature::new_both_same(
                    signature_tel_query,
                    0,
                )];
            teliox::query::SignedTelQuery::new_trans(
                tel_qry.clone(),
                signing_identifier.id.clone(),
                signatures,
            )
        }
    };

    let tel_url: url::Url = serde_json::from_value(serde_json::Value::String(
        "http://wa1.hcf.argo.colossi.network/query/tel".to_string(),
    ))
    .map_err(|_e| ())?;
    let tel_response = client
        .post(tel_url)
        .body(tel_query.to_cesr().unwrap())
        .send()
        .await
        .map_err(|e| {
            eprintln!("Request error: {:?}", e);
        })?;

    if !tel_response.status().is_success() {
        println!("Request failed with status: {}", tel_response.status());
        let error_text = tel_response.text().await.map_err(|_| ())?;
        println!("Error body: {}", error_text);
        return Err(());
    }

    let tel = tel_response.text().await.map_err(|_| ())?;
    println!("Tel: {}", tel);
    let _ = controller.process_tel(tel.as_bytes());
    let state = controller.get_vc_state(&vc_said).map_err(|_e| ())?;
    println!("VC said: {:?}", vc_said);
    println!("VC State: {:?}", state);

    Ok(())
}
