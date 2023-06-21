use std::sync::Arc;

use std::path::Path;

use keri::actor::prelude::{HashFunctionCode, SelfAddressingIdentifier};
use keri::event::sections::seal::{EventSeal, Seal};
use teliox::event::verifiable_event::VerifiableEvent;
use teliox::seal::{AttachedSourceSeal, EventSourceSeal};
use teliox::tel::Tel;

use crate::error::ControllerError;

use super::IdentifierController;

impl IdentifierController {
    /// Generate `vcp` event and `ixn` event with  seal to `vcp`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn incept_registry(
        &mut self,
        tel_db_path: impl AsRef<Path>,
    ) -> Result<Vec<u8>, ControllerError> {
        let tel_db = Arc::new(teliox::database::EventDatabase::new(tel_db_path).unwrap());

        // Create tel
        let mut tel = Tel::new(tel_db, self.source.storage);

        let vcp = tel
            .make_inception_event(
                self.id.clone(),
                vec![teliox::event::manager_event::Config::NoBackers],
                0,
                vec![],
            )
            .unwrap();

        let seal = Seal::Event(EventSeal {
            prefix: vcp.get_prefix(),
            sn: vcp.get_sn(),
            event_digest: vcp.get_digest().unwrap(),
        });
        let ixn = self.anchor_with_seal(&[seal])?;
        let source_seal = EventSourceSeal {
            sn: ixn.data.sn,
            digest: ixn.digest()?,
        };
        let encoded = ixn.encode()?;

        let verifiable_event = VerifiableEvent {
            event: vcp,
            seal: AttachedSourceSeal { seal: source_seal },
        };
        tel.process(verifiable_event).unwrap();
        self.tel = Some(tel);

        Ok(encoded)
    }

    /// Generate `iss` event and `ixn` event with  seal to `iss`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn issue(&self, credential: &str) -> Result<Vec<u8>, ControllerError> {
        match self.tel.as_ref() {
            Some(tel) => {
                let iss = tel
                    .make_issuance_event(HashFunctionCode::Blake3_256, credential)
                    .unwrap();

                let seal = Seal::Event(EventSeal {
                    prefix: iss.get_prefix(),
                    sn: iss.get_sn(),
                    event_digest: iss.get_digest().unwrap(),
                });
                let ixn = self.anchor_with_seal(&[seal])?;

                let source_seal = EventSourceSeal {
                    sn: ixn.data.sn,
                    digest: ixn.digest()?,
                };
                let encoded_ixn = ixn.encode()?;

                let verifiable_event = VerifiableEvent {
                    event: iss,
                    seal: AttachedSourceSeal { seal: source_seal },
                };
                tel.processor.process(verifiable_event).unwrap();

                Ok(encoded_ixn)
            }
            None => Err(ControllerError::OtherError("Tel not incepted".into())),
        }
    }

    /// Generate `rev` event and `ixn` event with  seal to `rev`. To finalize
    /// the process, `ixn` need to be signed confirmed with `finalize_event`
    /// function.
    pub fn revoke(
        &self,
        credential_sai: &SelfAddressingIdentifier,
    ) -> Result<Vec<u8>, ControllerError> {
        match &self.tel {
            Some(tel) => {
                let rev = tel.make_revoke_event(credential_sai).unwrap();

                let seal = Seal::Event(EventSeal {
                    prefix: rev.get_prefix(),
                    sn: rev.get_sn(),
                    event_digest: rev.get_digest().unwrap(),
                });
                let ixn = self.anchor_with_seal(&[seal])?;

                let source_seal = EventSourceSeal {
                    sn: ixn.data.sn,
                    digest: ixn.digest()?,
                };
                let encoded_ixn = ixn.encode()?;

                let verifiable_event = VerifiableEvent {
                    event: rev,
                    seal: AttachedSourceSeal { seal: source_seal },
                };
                tel.processor.process(verifiable_event).unwrap();

                Ok(encoded_ixn)
            }
            None => Err(ControllerError::OtherError("Tel not incepted".into())),
        }
    }
}
