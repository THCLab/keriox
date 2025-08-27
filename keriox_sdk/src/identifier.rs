use keri_core::{
    actor::{
        event_generator,
        prelude::{
            EventStorage, HashFunctionCode, Message, SerializationFormats,
        },
    },
    database::EventDatabase,
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Notice, Op},
        timestamped::Timestamped,
    },
    oobi::Role,
    prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix},
    query::{
        query_event::{LogsQueryArgs, QueryEvent, QueryRoute},
        reply_event::{ReplyEvent, ReplyRoute, SignedReply},
    },
};
use std::sync::Arc;
use teliox::query::{TelQueryArgs, TelQueryEvent, TelQueryRoute};

pub struct Identifier<D: EventDatabase> {
    pub id: IdentifierPrefix,
    event_storage: Arc<EventStorage<D>>,
}

impl<D: EventDatabase> Identifier<D> {
    pub fn new(
        id: IdentifierPrefix,
        event_storage: Arc<EventStorage<D>>,
    ) -> Self {
        Self { id, event_storage }
    }

    pub fn get_prefix(&self) -> &IdentifierPrefix {
        &self.id
    }

    pub fn get_own_kel(&self) -> Option<Vec<Notice>> {
        self.event_storage
            .get_kel_messages_with_receipts_all(&self.id)
            .unwrap()
    }

    pub fn add_watcher(
        &self,
        watcher_id: IdentifierPrefix,
    ) -> Result<String, String> {
        String::from_utf8(
            event_generator::generate_end_role(
                &self.id,
                &watcher_id,
                Role::Watcher,
                true,
            )
            .encode()
            .map_err(|_| "Event encoding error".to_string())?,
        )
        .map_err(|_| "Event format error".to_string())
    }

    pub fn finalize_add_watcher(
        &self,
        event: &[u8],
        sig: SelfSigningPrefix,
    ) -> Result<(IdentifierPrefix, Vec<Message>), String> {
        let parsed_event = parse_event_type(event)
            .map_err(|_| "Event parsing error".to_string())?;
        match parsed_event {
            EventType::Rpy(rpy) => match rpy.get_route() {
                ReplyRoute::EndRoleAdd(_) => Ok(self
                    .finalize_add_role(&self.id, rpy, vec![sig])
                    .unwrap()),
                ReplyRoute::EndRoleCut(_) => todo!(),
                _ => Err("Wrong reply route".to_string()),
            },
            _ => Err("Event is not a reply".to_string()),
        }
    }

    fn finalize_add_role(
        &self,
        signer_prefix: &IdentifierPrefix,
        event: ReplyEvent,
        sig: Vec<SelfSigningPrefix>,
    ) -> Result<(IdentifierPrefix, Vec<Message>), String> {
        let mut messages_to_send = vec![];
        let (dest_prefix, role) = match &event.data.data {
            ReplyRoute::EndRoleAdd(role) => {
                (role.eid.clone(), role.role.clone())
            }
            ReplyRoute::EndRoleCut(role) => {
                (role.eid.clone(), role.role.clone())
            }
            _ => return Err("Wrong reply route".to_string()),
        };
        let signed_reply = match signer_prefix {
            IdentifierPrefix::Basic(bp) => Message::Op(Op::Reply(
                SignedReply::new_nontrans(event, bp.clone(), sig[0].clone()),
            )),
            _ => {
                let sigs = sig
                    .into_iter()
                    .enumerate()
                    .map(|(i, sig)| {
                        IndexedSignature::new_both_same(sig, i as u16)
                    })
                    .collect();

                let signed_rpy =
                    Message::Op(Op::Reply(SignedReply::new_trans(
                        event,
                        self.event_storage
                            .get_last_establishment_event_seal(signer_prefix)
                            .ok_or(
                                "Failed to get last establishment event seal"
                                    .to_string(),
                            )?,
                        sigs,
                    )));
                if Role::Messagebox != role {
                    let kel = self
                        .event_storage
                        .get_kel_messages_with_receipts_all(signer_prefix)
                        .map_err(|_| "Failed to get KEL messages".to_string())?
                        .ok_or("Identifier not found".to_string())?;

                    for ev in kel {
                        messages_to_send.push(Message::Notice(ev));
                    }
                };
                signed_rpy
            }
        };

        messages_to_send.push(signed_reply.clone());
        Ok((dest_prefix, messages_to_send))
    }

    pub fn get_log_query(
        &self,
        identifier: IdentifierPrefix,
        witness: IdentifierPrefix,
    ) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: None,
                    limit: None,
                    i: identifier,
                    src: Some(witness),
                },
            },
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256,
        )
    }

    pub fn get_tel_query(
        &self,
        registry_id: IdentifierPrefix,
        vc_identifier: IdentifierPrefix,
    ) -> Result<TelQueryEvent, String> {
        let route = TelQueryRoute::Tels {
            reply_route: "".into(),
            args: TelQueryArgs {
                i: Some(vc_identifier),
                ri: Some(registry_id),
            },
        };
        let env = Timestamped::new(route);
        Ok(KeriEvent::new(
            SerializationFormats::JSON,
            HashFunctionCode::Blake3_256.into(),
            env,
        ))
    }
}
