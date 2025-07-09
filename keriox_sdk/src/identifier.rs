use std::sync::Arc;
use keri_core::{
    actor::prelude::{EventStorage, HashFunctionCode, SerializationFormats},
    database::EventDatabase,
    event_message::{
        msg::KeriEvent, signed_event_message::Notice, timestamped::Timestamped,
    },
    prefix::{BasicPrefix, IdentifierPrefix},
    query::query_event::{LogsQueryArgs, QueryEvent, QueryRoute},
};
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

    pub fn get_log_query(
        &self,
        identifier: IdentifierPrefix,
        sn: u64,
        limit: u64,
        witness: BasicPrefix,
    ) -> QueryEvent {
        QueryEvent::new_query(
            QueryRoute::Logs {
                reply_route: "".to_string(),
                args: LogsQueryArgs {
                    s: Some(sn),
                    i: identifier,
                    src: Some(IdentifierPrefix::Basic(witness)),
                    limit: Some(limit),
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
