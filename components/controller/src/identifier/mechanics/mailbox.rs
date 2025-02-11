use futures::{StreamExt, TryStreamExt};
use keri_core::{
    actor::event_generator,
    error::Error,
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
    },
    event_message::signed_event_message::{
        Message, Notice, SignedEventMessage, SignedNontransferableReceipt,
    },
    mailbox::{exchange::ForwardTopic, MailboxResponse},
    prefix::IdentifierPrefix,
};

use crate::{error::ControllerError, identifier::Identifier, mailbox_updating::ActionRequired};

use super::{MechanicsError, ResponseProcessingError};

impl Identifier {
    pub(crate) async fn mailbox_response(
        &self,
        recipient: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
        about_who: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        let req = if from_who == about_who {
            // process own mailbox
            let req = self.process_own_mailbox(res)?;
            self.query_cache.update_last_asked_index(recipient, res)?;
            req
        } else {
            // process group mailbox
            let group_req = self.process_group_mailbox(res, about_who).await?;
            self.query_cache
                .update_last_asked_group_index(recipient, res)?;
            group_req
        };
        Ok(req)
    }

    fn process_receipt(&self, receipt: &SignedNontransferableReceipt) -> Result<(), Error> {
        self.known_events
            .process(&Message::Notice(Notice::NontransferableRct(
                receipt.clone(),
            )))?;
        Ok(())
    }

    fn process_own_mailbox(
        &self,
        mb: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, MechanicsError> {
        for rct in &mb.receipt {
            self.process_receipt(rct)
                .map_err(ResponseProcessingError::Receipts)?;
        }

        Iterator::chain(
            mb.multisig
                .iter()
                .map(|event| self.process_own_multisig(event)),
            mb.delegate
                .iter()
                .map(|del_event| self.process_own_delegate(del_event))
                .filter_map(Result::transpose),
        )
        .collect()
    }

    async fn process_group_mailbox(
        &self,
        mb: &MailboxResponse,
        group_id: &IdentifierPrefix,
    ) -> Result<Vec<ActionRequired>, MechanicsError> {


        for event in mb.multisig.iter() {
            self.process_group_multisig(event).await?;
        }
        
        let action_required = futures::stream::iter(&mb.delegate)
            .then(|del_event| self.process_group_delegate(del_event, group_id))
            .try_filter_map(|del| async move { Ok(del) })
            .try_collect::<Vec<_>>()
            .await;

        for rct in &mb.receipt {
            self.process_receipt(rct)
                .map_err(ResponseProcessingError::Receipts)?;
        }
        action_required
    }

    /// Returns exn message that contains signed multisig event and will be
    /// forward to group identifier's mailbox.
    fn process_own_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<ActionRequired, MechanicsError> {
        self.known_events
            .process(&Message::Notice(Notice::Event(event.clone())))
            .map_err(ResponseProcessingError::Multisig)?;
        let event = event.event_message.clone();
        let receipient = event.data.get_prefix();
        // Construct exn message (will be stored in group identidfier mailbox)
        let exn = event_generator::exchange(&receipient, &event, ForwardTopic::Multisig);
        Ok(ActionRequired::MultisigRequest(event, exn))
    }

    /// If leader and event is fully signed publish event to witness.
    async fn process_group_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<(), MechanicsError> {
        self.known_events
            .process(&Message::Notice(Notice::Event(event.clone())))
            .map_err(ResponseProcessingError::Multisig)?;

        self.publish(event).await
    }

    async fn publish(&self, event: &SignedEventMessage) -> Result<(), MechanicsError> {
        let id = event.event_message.data.get_prefix();
        let fully_signed_event = self
            .known_events
            .partially_witnessed_escrow
            .get_event_by_sn_and_digest(
                event.event_message.data.get_sn(),
                &id,
                &event.event_message.digest()?,
            );

        let own_index = self.get_index(&event.event_message.data)?;
        // Elect the leader
        // Leader is identifier with minimal index among all participants who
        // sign event. He will send message to witness.
        let to_publish = fully_signed_event.and_then(|ev| {
            ev.signatures
                .iter()
                .map(|at| at.index.current())
                .min()
                .and_then(|index| {
                    if index as usize == own_index {
                        Some(ev)
                    } else {
                        None
                    }
                })
        });

        match to_publish {
            Some(to_publish) => {
                let witnesses = self
                    .known_events
                    .get_state_at_event(&to_publish.event_message)?
                    .witness_config
                    .witnesses;
                self.communication.publish(witnesses, &to_publish).await
            }
            None => Ok(()),
        }
    }

    /// Process event from delegate mailbox. If signing is required to finish
    /// the process it returns proper notification.
    fn process_own_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
    ) -> Result<Option<ActionRequired>, MechanicsError> {
        match event_to_confirm.event_message.data.get_event_data() {
            // delegating event
            EventData::Icp(_) | EventData::Rot(_) | EventData::Ixn(_) => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                Ok(None)
            }
            // delegated event
            EventData::Dip(_) | EventData::Drt(_) => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                let (delegating_event, exn) = self.delegate(&event_to_confirm.event_message)?;
                Ok(Some(ActionRequired::DelegationRequest(
                    delegating_event,
                    exn,
                )))
            }
        }
    }

    /// Process event from group delegate mailbox. Creates group delegating
    /// event and send it to group multisig mailbox for other group
    /// participants. If signing is required to finish the process it returns
    /// proper notification.
    async fn process_group_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
        group_id: &IdentifierPrefix,
    ) -> Result<Option<ActionRequired>, MechanicsError> {
        match event_to_confirm.event_message.data.get_event_data() {
            // delegating event
            EventData::Ixn(ixn) => {
                //| EventData::Rot(_) | EventData::Ixn(_) => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                if let Seal::Event(seal) = ixn.data[0].clone() {
                    let fully_signed_event = self
                        .known_events
                        .partially_witnessed_escrow
                        .get_event_by_sn_and_digest(seal.sn, &seal.prefix, &seal.event_digest());
                    if let Some(fully_signed) = fully_signed_event {
                        let witnesses = self.known_events.get_current_witness_list(&self.id)?;
                        self.communication.publish(witnesses, &fully_signed).await?;
                    };
                };
                Ok(None)
            }
            // delegated event
            EventData::Dip(_) | EventData::Drt(_) => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                let id = event_to_confirm.event_message.data.get_prefix();

                let seal = Seal::Event(EventSeal::new(
                    id,
                    event_to_confirm.event_message.data.get_sn(),
                    event_to_confirm.event_message.digest()?,
                ));

                let ixn = self.known_events.anchor_with_seal(group_id, &[seal])?;
                let exn = event_generator::exchange(group_id, &ixn, ForwardTopic::Multisig);
                // let (delegating_event, exn) = self.delegate(&event_to_confirm.event_message)?;
                Ok(Some(ActionRequired::DelegationRequest(ixn, exn)))
            }
            _ => todo!(),
        }
    }
}
