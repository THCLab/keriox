use std::sync::Arc;

use crate::{
    database::sled::SledEventDatabase, error::Error, event_message::signed_event_message::Message,
    query::QueryError, state::IdentifierState,
};

use super::{compute_state, validator::EventValidator};

pub struct WitnessProcessor {
    db: Arc<SledEventDatabase>,
    validator: EventValidator,
}

impl WitnessProcessor {
    pub fn new(db: Arc<SledEventDatabase>) -> Self {
        let validator = EventValidator::new(db.clone());
        Self { db, validator }
    }

    /// Process
    ///
    /// Process a deserialized KERI message
    pub fn process(&self, message: Message) -> Result<Option<IdentifierState>, Error> {
        match message {
            Message::Event(signed_event) => {
                let id = &signed_event.event_message.event.get_prefix();
                match self.validator.process_event(&signed_event) {
                    Ok(_) | Err(Error::NotEnoughReceiptsError) => {
                        self.db.add_kel_finalized_event(signed_event.clone(), id)?;
                        self.process_nt_receipts_escrow()
                    }
                    Err(e) => {
                        match e {
                            Error::EventDuplicateError => {
                                self.db.add_duplicious_event(signed_event.clone(), id)
                            }
                            _ => Ok(()),
                        }?;
                        Err(e)
                    }
                }?;
                Ok(compute_state(self.db.clone(), id)?)
            }

            Message::NontransferableRct(rct) => {
                let id = &rct.body.event.prefix;
                match self.validator.process_witness_receipt(&rct) {
                    Ok(_) => self.db.add_receipt_nt(rct.to_owned(), id)?,
                    Err(Error::MissingEvent) => {
                        self.db.add_escrow_nt_receipt(rct.to_owned(), id)?
                    }
                    Err(e) => return Err(e),
                };
                Ok(compute_state(self.db.clone(), id)?)
            }
            Message::TransferableRct(vrc) => {
                match self.validator.process_validator_receipt(&vrc) {
                    Ok(_) => self.db.add_receipt_t(vrc.clone(), &vrc.body.event.prefix),
                    Err(Error::MissingEvent) => self
                        .db
                        .add_escrow_t_receipt(vrc.clone(), &vrc.body.event.prefix),
                    Err(e) => Err(e),
                }?;
                let id = vrc.body.event.prefix;
                Ok(compute_state(self.db.clone(), &id)?)
            }
            #[cfg(feature = "query")]
            Message::KeyStateNotice(rpy) => {
                match self.validator.process_signed_reply(&rpy) {
                    Ok(_) => self
                        .db
                        .update_accepted_reply(rpy.clone(), &rpy.reply.event.get_prefix()),
                    Err(Error::EventOutOfOrderError) => {
                        let id = rpy.reply.event.get_prefix();
                        self.db.add_escrowed_reply(rpy.clone(), &id)?;
                        Err(Error::QueryError(QueryError::OutOfOrderEventError))
                    }
                    Err(Error::QueryError(QueryError::OutOfOrderEventError)) => {
                        let id = rpy.reply.event.get_prefix();
                        self.db.add_escrowed_reply(rpy.clone(), &id)?;
                        Err(Error::QueryError(QueryError::OutOfOrderEventError))
                    }
                    Err(anything) => Err(anything),
                }?;
                Ok(None)
            }
            #[cfg(feature = "query")]
            Message::Query(_qry) => todo!(),
        }
    }

    fn process_nt_receipts_escrow(&self) -> Result<(), Error> {
        if let Some(esc) = self.db.get_all_escrow_nt_receipts() {
            esc.for_each(|sig_receipt| {
                match self.validator.process_witness_receipt(&sig_receipt) {
                    Ok(_) | Err(Error::SignatureVerificationError) => {
                        // remove from escrow
                        self.db
                            .remove_escrow_nt_receipt(&sig_receipt.body.event.prefix, &sig_receipt)
                            .unwrap();
                    }
                    Err(_e) => {} // keep in escrow,
                }
            })
        };

        Ok(())
    }
}
