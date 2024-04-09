use std::sync::Arc;

use keri_core::{
    actor::{error::ActorError, simple_controller::PossibleResponse},
    event_message::signed_event_message::{Message, Notice, Op, SignedEventMessage},
    oobi::{EndRole, LocationScheme, Oobi, Scheme},
    prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    query::{query_event::SignedKelQuery, reply_event::ReplyEvent},
    transport::Transport,
};
use teliox::transport::GeneralTelTransport;

use crate::{error::ControllerError, known_events::KnownEvents};

pub struct Communication {
    pub events: Arc<KnownEvents>,
    pub transport: Box<dyn Transport + Send + Sync>,
    pub tel_transport: Box<dyn GeneralTelTransport + Send + Sync>,
}

impl Communication {
    pub fn new(
        known_events: Arc<KnownEvents>,
        transport: Box<dyn Transport<ActorError> + Send + Sync>,
        tel_transport: Box<dyn GeneralTelTransport + Send + Sync>,
    ) -> Self {
        Communication {
            events: known_events,
            transport,
            tel_transport,
        }
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_loc_schema(&self, lc: &LocationScheme) -> Result<(), ControllerError> {
        let oobis = self.transport.request_loc_scheme(lc.clone()).await?;
        for oobi in oobis {
            self.events.save(&Message::Op(oobi))?;
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_end_role(&self, er: &EndRole) -> Result<(), ControllerError> {
        let EndRole { cid, role, eid } = er.clone();
        // TODO what if more than one
        let loc = self
            .events
            .get_loc_schemas(&cid)?
            .first()
            .ok_or(ControllerError::UnknownIdentifierError)?
            .clone();
        let msgs = self.transport.request_end_role(loc, cid, role, eid).await?;
        for msg in msgs {
            // TODO This ignore signatures. Add verification.
            if let Message::Op(Op::Reply(signed_oobi)) = msg {
                self.events.save_oobi(&signed_oobi)?;
            } else {
                self.events.save(&msg)?;
            }
        }
        Ok(())
    }

    /// Make http request to get identifier's endpoints information.
    pub async fn resolve_oobi(&self, oobi: &Oobi) -> Result<(), ControllerError> {
        match oobi {
            Oobi::Location(loc) => self.resolve_loc_schema(loc).await,
            Oobi::EndRole(er) => self.resolve_end_role(er).await,
        }
    }

    pub async fn send_message_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        msg: Message,
    ) -> Result<(), ControllerError> {
        let loc = self.events.find_location(id, scheme)?;
        self.transport.send_message(loc, msg).await?;
        Ok(())
    }

    pub async fn send_query_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        query: SignedKelQuery,
    ) -> Result<PossibleResponse, ControllerError> {
        let loc = self.events.find_location(id, scheme)?;
        Ok(self.transport.send_query(loc, query).await?)
    }

    async fn send_oobi_to(
        &self,
        id: &IdentifierPrefix,
        scheme: Scheme,
        oobi: Oobi,
    ) -> Result<(), ControllerError> {
        let loc = self.events.find_location(id, scheme)?;
        self.transport.resolve_oobi(loc, oobi).await?;
        Ok(())
    }

    /// Publish key event to witnesses
    ///
    ///  1. send it to all witnesses
    ///  2. collect witness receipts and process them
    ///  3. get processed receipts from db and send it to all witnesses
    pub async fn publish(
        &self,
        witness_prefixes: &[BasicPrefix],
        message: &SignedEventMessage,
    ) -> Result<(), ControllerError> {
        for id in witness_prefixes {
            self.send_message_to(
                &IdentifierPrefix::Basic(id.clone()),
                Scheme::Http,
                Message::Notice(Notice::Event(message.clone())),
            )
            .await?;
            // process collected receipts
            // send query message for receipt mailbox
            // TODO: get receipts from mailbox
            // for receipt in receipts {
            //     self.process(&receipt)?;
            // }
        }

        // Get processed receipts from database to send all of them to witnesses. It
        // will return one receipt with all witness signatures as one attachment,
        // not three separate receipts as in `collected_receipts`.
        let (prefix, sn, digest) = (
            message.event_message.data.get_prefix(),
            message.event_message.data.get_sn(),
            message.event_message.digest(),
        );
        let rcts_from_db = self.events.find_receipt(&prefix, sn, &digest?)?;

        if let Some(receipt) = rcts_from_db {
            // send receipts to all witnesses
            for prefix in witness_prefixes {
                self.send_message_to(
                    &IdentifierPrefix::Basic(prefix.clone()),
                    Scheme::Http,
                    Message::Notice(Notice::NontransferableRct(receipt.clone())),
                )
                .await?;
            }
        };

        Ok(())
    }

    /// Sends identifier's endpoint information to identifiers's watchers.
    // TODO use stream instead of json
    pub async fn send_oobi_to_watcher(
        &self,
        id: &IdentifierPrefix,
        oobi: &Oobi,
    ) -> Result<(), ControllerError> {
        for watcher in self.events.get_watchers(id)?.iter() {
            self.send_oobi_to(watcher, Scheme::Http, oobi.clone())
                .await?;
        }

        Ok(())
    }
}
