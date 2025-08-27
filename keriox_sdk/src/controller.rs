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
        escrow::{default_escrow_bus, EscrowConfig},
        Processor,
    },
};
use teliox::{
    database::TelEventDatabase, processor::storage::TelEventStorage,
    state::vc_state::TelState, tel::Tel,
};

use crate::Identifier;

pub struct Controller<D: EventDatabase + 'static, T: TelEventDatabase> {
    processor: Arc<BasicProcessor<D>>,
    event_storage: Arc<EventStorage<D>>,
    tel: Arc<Tel<T, D>>,
}

impl<
        D: EventDatabase + EscrowCreator + Send + Sync + 'static,
        T: TelEventDatabase,
    > Controller<D, T>
{
    pub fn new(event_db: Arc<D>, tel_db: Arc<T>) -> Self {
        let (not_bus, _) =
            default_escrow_bus(event_db.clone(), EscrowConfig::default());

        let processor =
            Arc::new(BasicProcessor::new(event_db.clone(), Some(not_bus)));

        let kel_storage = Arc::new(EventStorage::new(event_db.clone()));
        let tel_storage = Arc::new(TelEventStorage::new(tel_db));
        let tel =
            Arc::new(Tel::new(tel_storage.clone(), kel_storage.clone(), None));

        Self {
            processor,
            event_storage: kel_storage,
            tel,
        }
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

        Ok(Identifier::new(id_prefix, self.event_storage.clone()))
    }

    pub fn load_identifier(
        &self,
        id: &IdentifierPrefix,
    ) -> Result<Identifier<D>, String> {
        self.event_storage
            .get_kel_messages_with_receipts_all(id)
            .map_err(|e| e.to_string())
            .and_then(|kel| {
                if kel.is_none_or(|v| v.is_empty()) {
                    Err("No KEL found for the identifier".to_string())
                } else {
                    Ok(Identifier::new(id.clone(), self.event_storage.clone()))
                }
            })
    }

    pub fn process_kel(&self, messages: &[Message]) -> Result<(), String> {
        messages.iter().try_for_each(|msg| match msg {
            Message::Notice(notice) => self
                .processor
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
        self.processor
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
