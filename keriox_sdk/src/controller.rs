use std::sync::Arc;

use keri_core::{
    actor::{event_generator, prelude::EventStorage},
    database::{EscrowCreator, EventDatabase},
    event::{event_data::EventData, KeyEvent},
    event_message::{
        cesr_adapter::{parse_event_type, EventType},
        msg::KeriEvent,
        signed_event_message::{Message, Notice},
    },
    prefix::{
        BasicPrefix, IdentifierPrefix, IndexedSignature, SelfSigningPrefix,
    },
    processor::{
        basic_processor::BasicProcessor,
        escrow::{default_escrow_bus, EscrowConfig, EscrowSet},
        notification::NotificationBus,
        Processor,
    }, state::IdentifierState,
};
use teliox::{
    database::TelEventDatabase, processor::storage::TelEventStorage,
    state::vc_state::TelState, tel::Tel,
};

use crate::Identifier;

pub struct KeriRuntime<D: EventDatabase + EscrowCreator + Send + Sync + 'static> {
    pub processor: Arc<BasicProcessor<D>>,
    pub storage: Arc<EventStorage<D>>,
    pub escrows: EscrowSet<D>,
    pub notification_bus: NotificationBus,
}

impl<D: EventDatabase + EscrowCreator + Send + Sync + 'static> KeriRuntime<D> {
    pub fn new(event_db: Arc<D>) -> Self {
        Self::with_config(event_db, EscrowConfig::default(), None)
    }

    pub fn with_config(
        event_db: Arc<D>,
        escrow_config: EscrowConfig,
        notification_bus: Option<NotificationBus>,
    ) -> Self {
        let (bus, escrows) =
            default_escrow_bus(event_db.clone(), escrow_config, notification_bus);

        let processor =
            Arc::new(BasicProcessor::new(event_db.clone(), Some(bus.clone())));
        let storage = Arc::new(EventStorage::new(event_db));

        Self {
            processor,
            storage,
            escrows,
            notification_bus: bus,
        }
    }
}

pub struct Controller<D: EventDatabase + EscrowCreator + Send + Sync + 'static, T: TelEventDatabase> {
    pub kel: KeriRuntime<D>,
    pub tel: Arc<Tel<T, D>>,
}

impl<
        D: EventDatabase + EscrowCreator + Send + Sync + 'static,
        T: TelEventDatabase,
    > Controller<D, T>
{
    pub fn new(event_db: Arc<D>, tel_db: Arc<T>) -> Self {
        let kel = KeriRuntime::new(event_db);

        let tel_storage = Arc::new(TelEventStorage::new(tel_db));
        let tel =
            Arc::new(Tel::new(tel_storage.clone(), kel.storage.clone(), None));

        Self { kel, tel }
    }

    pub fn incept(
        &self,
        public_keys: Vec<BasicPrefix>,
        next_pub_keys: Vec<BasicPrefix>,
    ) -> Result<String, ()> {
        event_generator::incept(public_keys, next_pub_keys, vec![], 0, None)
            .map_err(|_e| ())
    }

    pub fn finalize_incept(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<Identifier<D>, ()> {
        let id_prefix = self.finalize_inception(event, sig)?;

        Ok(Identifier::new(id_prefix, self.kel.storage.clone()))
    }

    pub fn load_identifier(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Identifier<D>, String> {
        self.kel.storage
            .get_kel_messages_with_receipts_all(id)
            .map_err(|e| e.to_string())
            .and_then(|kel| {
                if kel.is_none_or(|v| v.is_empty()) {
                    Err("No KEL found for the identifier".to_string())
                } else {
                    Ok(Identifier::new(id.clone(), self.kel.storage.clone()))
                }
            })
    }

    pub fn process_kel(&self, messages: &[Message]) -> Result<(), String> {
        messages.iter().try_for_each(|msg| match msg {
            Message::Notice(notice) => self
                .kel.processor
                .process_notice(notice)
                .map_err(|e| e.to_string()),
            Message::Op(_) => {
                Err("Operation messages are not supported".to_string())
            }
        })?;

        Ok(())
    }

    pub fn process_tel(&self, tel: &[u8]) -> Result<(), String> {
        self.tel
            .parse_and_process_tel_stream(tel)
            .map_err(|e| e.to_string())
    }

    pub fn get_vc_state(
        &self,
        vc_hash: &said::SelfAddressingIdentifier,
    ) -> Result<Option<TelState>, String> {
        self.tel.get_vc_state(vc_hash).map_err(|e| e.to_string())
    }

    pub fn get_state(&self, id: &IdentifierPrefix) -> Option<IdentifierState> {
        self.kel.storage.get_state(id)
    }

    fn finalize_inception(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<IdentifierPrefix, ()> {
        let parsed_event = parse_event_type(event).map_err(|_e| ())?;
        match parsed_event {
            EventType::KeyEvent(ke) => {
                if let EventData::Icp(_) = &ke.data.get_event_data() {
                    self.finalize_key_event(&ke, sig, 0)?;
                    Ok(ke.data.get_prefix())
                } else {
                    Err(())
                }
            }
            _ => Err(()),
        }
    }

    fn finalize_key_event(
        &self,
        event: &KeriEvent<KeyEvent>,
        sig: &SelfSigningPrefix,
        own_index: usize,
    ) -> Result<(), ()> {
        let signature =
            IndexedSignature::new_both_same(sig.clone(), own_index as u16);

        let signed_message = event.sign(vec![signature], None, None);
        self.kel.processor
            .process_notice(&Notice::Event(signed_message))
            .map_err(|_e| ())?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use keri_core::database::redb::RedbDatabase;
    use teliox::database::{redb::RedbTelDatabase, TelEventDatabase};

    use super::*;
    use std::sync::Arc;
    use tempfile::Builder;

    #[test]
    fn test_incept() {
        let root = Builder::new().prefix("test-db").tempdir().unwrap();
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

        let controller = Controller::new(event_database, tel_events_db);
        let public_keys = vec![];
        let next_pub_keys = vec![];

        let result = controller.incept(public_keys, next_pub_keys);
        assert!(result.is_ok());
    }
}
