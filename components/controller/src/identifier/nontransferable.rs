use std::sync::Arc;

use crate::{communication::Communication, error::ControllerError, known_events::KnownEvents, BasicPrefix, IdentifierPrefix, LocationScheme, SeedPrefix, SelfSigningPrefix};
use keri_core::{actor::{prelude::{HashFunctionCode, SerializationFormats}, simple_controller::PossibleResponse}, event::sections::seal::EventSeal, event_message::signature::{Nontransferable, Signature}, oobi::Scheme, processor::escrow::EscrowConfig, query::query_event::{LogsQueryArgs, QueryEvent, QueryRoute, SignedKelQuery}, signer::Signer, transport::default::DefaultTransport};

pub struct NontransferableIdentifier {
	id: BasicPrefix,
	communication: Arc<Communication>,

}

impl NontransferableIdentifier {
	pub fn new(public_key: BasicPrefix, communication: Arc<Communication>,) -> Self {
		Self {id: public_key, communication }
	}

	pub fn sign(&self, signature: Vec<u8>) -> Signature {
		Signature::NonTransferable(Nontransferable::Couplet(vec![(self.id.clone() , SelfSigningPrefix::Ed25519Sha512(signature))]))
	}

	pub fn query_log(
        &self,
        seal: &EventSeal,
        witness: BasicPrefix,
    ) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(seal.sn),
                    i: seal.prefix.clone(),
                    src: Some(IdentifierPrefix::Basic(witness)),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )
    }

	pub fn query_ksn(
        &self,
        id: &IdentifierPrefix,
        witness: BasicPrefix,
    ) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Ksn {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: None,
                    i: id.clone(),
                    src: Some(IdentifierPrefix::Basic(witness)),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )
    }

	pub async fn finalize_query(&self, witness: LocationScheme, qry: QueryEvent, signature: Signature) -> Result<PossibleResponse, ControllerError> {
		self.communication.resolve_loc_schema(&witness).await?;
		let signed_qry = SignedKelQuery { query: qry, signature: signature };
            
        Ok(self.communication
            .send_query_to(&witness.eid, Scheme::Http, signed_qry)
            .await?)

	}
}

#[async_std::test]
pub async fn test() {
	use teliox::transport::TelTransport;
	use tempfile::Builder;

	let tmp_dir = Builder::new().prefix("tmp-dir").tempdir().unwrap();
	let transport = Box::new(DefaultTransport::new());
    let tel_transport = Box::new(TelTransport);

    let events = Arc::new(KnownEvents::new(tmp_dir.path().to_path_buf(), EscrowConfig::default()).unwrap());
	let comm = Arc::new(Communication {
            events: events.clone(),
            transport,
            tel_transport,
        });

	let seed: SeedPrefix = "ALjR-EE3jUF2yXW7Tq7WJSh3OFc6-BNxXJ9jGdfwA6Bs".parse().unwrap();
	let signer = Signer::new_with_seed(&seed).unwrap();
	let bp = BasicPrefix::new(cesrox::primitives::codes::basic::Basic::Ed25519Nontrans, signer.public_key());
	let id = NontransferableIdentifier::new(bp, comm);
	let seal = EventSeal::new("EFFzENba7P9zvWWueChAmVj3tpuwtXxuKqXwnXjKfPvc".parse().unwrap(), 1, "EFFzENba7P9zvWWueChAmVj3tpuwtXxuKqXwnXjKfPvc".parse().unwrap());
	let witness: LocationScheme = serde_json::from_str(r#"{"eid":"BJq7UABlttINuWJh1Xl2lkqZG4NTdUdqnbFJDa6ZyxCC","scheme":"http","url":"http://localhost:3232/"}"#).unwrap();

	let witness_id = match &witness.eid {
		IdentifierPrefix::Basic(basic_prefix) => basic_prefix.clone(),
		IdentifierPrefix::SelfAddressing(_said_value) => todo!(),
		IdentifierPrefix::SelfSigning(_self_signing_prefix) => todo!(),
	};
	let qry = id.query_log(&seal, witness_id);
	let signature = signer.sign(qry.encode().unwrap()).unwrap();
	let sig = id.sign(signature);

	let resp = id.finalize_query(witness, qry, sig).await;
    dbg!(resp);

}