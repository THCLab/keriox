use std::{convert::TryFrom, path::Path, sync::Arc};

use crate::{
    derivation::{basic::Basic, self_addressing::SelfAddressing, self_signing::SelfSigning},
    error::Error,
    event::{receipt::Receipt, EventMessage, SerializationFormats},
    event_message::{
        event_msg_builder::ReceiptBuilder,
        key_event_message::KeyEvent,
        signed_event_message::{Message, SignedNontransferableReceipt},
    },
    event_parsing::message::signed_event_stream,
    oobi::{LocationScheme, OobiManager, Role},
    prefix::{BasicPrefix, IdentifierPrefix},
    processor::{notification::Notification, responder::Responder, Processor},
    query::{
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
        ReplyType,
    },
    signer::Signer,
};

use super::Component;

pub struct NontransferableComponent<P: Processor> {
    pub prefix: BasicPrefix,
    pub component: Component<P>,
    pub signer: Arc<Signer>,
    pub oobi_manager: Arc<OobiManager>,
    responder: Arc<Responder<Notification>>,
}

impl<P: Processor> NontransferableComponent<P> {
    pub fn setup(
        public_address: url::Url,
        event_db_path: &Path,
        oobi_db_path: &Path,
        priv_key: Option<String>,
    ) -> Result<Self, Error> {
        let oobi_manager = Arc::new(OobiManager::new(oobi_db_path));
        let signer = priv_key
            .map(|key| Signer::new_with_seed(&key.parse()?))
            .unwrap_or(Ok(Signer::new()))?;
        let prefix = Basic::Ed25519.derive(signer.public_key());
        let witness = Component::<P>::new(event_db_path)?;
        // construct witness loc scheme oobi
        let loc_scheme = LocationScheme::new(
            IdentifierPrefix::Basic(prefix.clone()),
            public_address.scheme().parse().unwrap(),
            public_address.clone(),
        );
        let reply = ReplyEvent::new_reply(
            ReplyRoute::LocScheme(loc_scheme),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;
        let signed_reply = SignedReply::new_nontrans(
            reply.clone(),
            prefix.clone(),
            SelfSigning::Ed25519Sha512.derive(signer.sign(reply.serialize()?)?),
        );
        oobi_manager.save_oobi(signed_reply)?;
        let responder = Arc::new(Responder::new());
        Ok(Self {
            prefix,
            component: witness,
            oobi_manager,
            signer: Arc::new(signer),
            responder,
        })
    }

    pub fn respond(&self, signer: Arc<Signer>) -> Result<Vec<Message>, Error> {
        let response = Vec::new();
        while let Some(event) = self.responder.get_data_to_respond() {
            match event {
                Notification::KeyEventAdded(event) => {
                    let non_trans_receipt =
                        self.respond_to_key_event(event.event_message, signer.clone())?;
                    self.component
                        .storage
                        .add_mailbox_receipt(non_trans_receipt)?;
                }
                _ => return Err(Error::SemanticError("Wrong notification type".into())),
            }
        }
        Ok(response)
    }

    fn respond_to_key_event(
        &self,
        event_message: EventMessage<KeyEvent>,
        signer: Arc<Signer>,
    ) -> Result<SignedNontransferableReceipt, Error> {
        // Create witness receipt and add it to db
        let ser = event_message.serialize()?;
        let signature = signer.sign(&ser)?;
        let rcp = ReceiptBuilder::default()
            .with_receipted_event(event_message)
            .build()?;

        let signature = SelfSigning::Ed25519Sha512.derive(signature);

        let signed_rcp = SignedNontransferableReceipt::new(
            &rcp,
            Some(vec![(self.prefix.clone(), signature)]),
            None,
        );

        self.component
            .processor
            .process(Message::NontransferableRct(signed_rcp.clone()))?;
        Ok(signed_rcp)
    }

    pub fn get_signed_ksn_for_prefix(
        &self,
        prefix: &IdentifierPrefix,
        signer: Arc<Signer>,
    ) -> Result<SignedReply, Error> {
        let ksn = self.component.get_ksn_for_prefix(prefix)?;
        let rpy = ReplyEvent::new_reply(
            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
            SelfAddressing::Blake3_256,
            SerializationFormats::JSON,
        )?;

        let signature = SelfSigning::Ed25519Sha512.derive(signer.sign(&rpy.serialize()?)?);
        Ok(SignedReply::new_nontrans(
            rpy,
            self.prefix.clone(),
            signature,
        ))
    }

    pub fn get_end_role_for_id(
        &self,
        cid: &IdentifierPrefix,
        role: Role,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
        Ok(self.oobi_manager.get_end_role(cid, role).unwrap())
    }

    pub fn get_loc_scheme_for_id(
        &self,
        eid: &IdentifierPrefix,
    ) -> Result<Option<Vec<SignedReply>>, Error> {
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

    // Returns messages if they can be returned immediately, i.e. for query message
    pub fn process(&self, msg: Message) -> Result<Vec<Message>, Error> {
        let mut responses = Vec::new();
        match msg.clone() {
            Message::Event(ev) => {
                self.component.process(&msg).unwrap();
                // check if receipts are attached
                if let Some(witness_receipts) = ev.witness_receipts {
                    // Create and process witness receipts
                    // TODO What timestamp should be set?
                    let id = ev.event_message.event.get_prefix();
                    let receipt = Receipt {
                        receipted_event_digest: ev.event_message.get_digest(),
                        prefix: id,
                        sn: ev.event_message.event.get_sn(),
                    };
                    let signed_receipt = SignedNontransferableReceipt::new(
                        &receipt.to_message(SerializationFormats::JSON).unwrap(),
                        None,
                        Some(witness_receipts),
                    );
                    self.component
                        .process(&Message::NontransferableRct(signed_receipt))
                        .unwrap();
                }
            }
            Message::Query(qry) => {
                let response = self.component.process_signed_query(qry).unwrap();
                match response {
                    ReplyType::Ksn(ksn) => {
                        let rpy = ReplyEvent::new_reply(
                            ReplyRoute::Ksn(IdentifierPrefix::Basic(self.prefix.clone()), ksn),
                            SelfAddressing::Blake3_256,
                            SerializationFormats::JSON,
                        )?;

                        let signature =
                            SelfSigning::Ed25519Sha512.derive(self.signer.sign(&rpy.serialize()?)?);
                        let reply = Message::Reply(SignedReply::new_nontrans(
                            rpy,
                            self.prefix.clone(),
                            signature,
                        ));
                        responses.push(reply);
                    }
                    ReplyType::Kel(msgs) | ReplyType::Mbx(msgs) => responses.extend(msgs),
                };
            }
            Message::Reply(reply) => match reply.reply.get_route() {
                ReplyRoute::Ksn(_, _) => self.component.process(&msg).unwrap(),
                ReplyRoute::LocScheme(_)
                | ReplyRoute::EndRoleAdd(_)
                | ReplyRoute::EndRoleCut(_) => self.oobi_manager.process_oobi(reply).unwrap(),
            },
            _ => self.component.process(&msg).unwrap(),
        };
        Ok(responses)
    }

    pub fn parse_and_process(&self, input_stream: &[u8]) -> Result<Vec<Message>, Error> {
        let (_, msgs) = signed_event_stream(input_stream)
            .map_err(|e| Error::DeserializeError(e.to_string()))
            .unwrap();

        let output = msgs
            .into_iter()
            .map(|msg| -> Result<_, _> {
                let msg = Message::try_from(msg)?;
                self.process(msg)
            })
            // TODO: avoid unwrap
            .map(|d| d.unwrap())
            .flatten()
            .collect();
        Ok(output)
    }
}
