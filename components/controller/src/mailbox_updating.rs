use super::{error::ControllerError, identifier_controller::IdentifierController};
use futures::{StreamExt, TryStreamExt};
use keri::{
    actor::{event_generator, prelude::Message},
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
        KeyEvent,
    },
    event_message::{
        msg::KeriEvent,
        signed_event_message::{Notice, SignedEventMessage, SignedNontransferableReceipt},
    },
    mailbox::{
        exchange::{ExchangeMessage, ForwardTopic},
        MailboxResponse,
    },
    prefix::IdentifierPrefix,
    sai::sad::SAD,
};

#[derive(Default, Debug, Clone)]
/// Struct for tracking what was the last indexes of processed mailbox messages.
/// Events in mailbox aren't removed after getting them, so it prevents
/// processing the same event multiple times.
pub struct MailboxReminder {
    pub receipt: usize,
    pub multisig: usize,
    pub delegate: usize,
}

#[derive(Debug)]
pub enum ActionRequired {
    MultisigRequest(KeriEvent<KeyEvent>, ExchangeMessage),
    // Contains delegating event and exchange message that will be send to
    // delegate after delegating event confirmation.
    DelegationRequest(KeriEvent<KeyEvent>, ExchangeMessage),
}

impl IdentifierController {
    pub fn process_receipt(
        &self,
        receipt: &SignedNontransferableReceipt,
    ) -> Result<(), ControllerError> {
        self.source
            .process(&Message::Notice(Notice::NontransferableRct(
                receipt.clone(),
            )))?;
        Ok(())
    }

    pub fn process_own_mailbox(
        &self,
        mb: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        for rct in &mb.receipt {
            self.process_receipt(rct)?;
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

    pub async fn process_groups_mailbox(
        &self,
        groups: Vec<IdentifierPrefix>,
        mb: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        futures::stream::iter(&groups)
            .then(|group_id| self.process_group_mailbox(mb, group_id))
            .try_concat()
            .await
    }

    pub async fn process_group_mailbox(
        &self,
        mb: &MailboxResponse,
        group_id: &IdentifierPrefix,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        for rct in &mb.receipt {
            self.process_receipt(rct)?;
        }

        for event in mb.multisig.iter() {
            self.process_group_multisig(&event).await?;
        }

        futures::stream::iter(&mb.delegate)
            .then(|del_event| self.process_group_delegate(del_event, group_id))
            .try_filter_map(|del| async move { Ok(del) })
            .try_collect::<Vec<_>>()
            .await
    }

    /// Returns exn message that contains signed multisig event and will be
    /// forward to group identifier's mailbox.
    fn process_own_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<ActionRequired, ControllerError> {
        self.source
            .process(&Message::Notice(Notice::Event(event.clone())))?;
        let event = event.event_message.clone();
        let receipient = event.data.get_prefix();
        // Construct exn message (will be stored in group identidfier mailbox)
        let exn = event_generator::exchange(&receipient, &event, ForwardTopic::Multisig)?;
        Ok(ActionRequired::MultisigRequest(event, exn))
    }

    /// If leader and event is fully signed publish event to witness.
    async fn process_group_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<(), ControllerError> {
        self.source
            .process(&Message::Notice(Notice::Event(event.clone())))?;

        self.publish(event).await
    }

    async fn publish(&self, event: &SignedEventMessage) -> Result<(), ControllerError> {
        let id = event.event_message.data.get_prefix();
        let fully_signed_event = self
            .source
            .partially_witnessed_escrow
            .get_event_by_sn_and_digest(
                event.event_message.data.get_sn(),
                &id,
                &event.event_message.get_digest(),
            );

        let own_index = self.get_index(&event.event_message.data)?;
        // Elect the leader
        // Leader is identifier with minimal index among all participants who
        // sign event. He will send message to witness.
        let to_publish = fully_signed_event.and_then(|ev| {
            ev.signatures
                .iter()
                .map(|at| at.index)
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
                    .source
                    .get_witnesses_at_event(&to_publish.event_message)?;
                self.source.publish(&witnesses, &to_publish).await
            }
            None => Ok(()),
        }
    }

    /// Process event from delegate mailbox. If signing is required to finish
    /// the process it resturns proper notification.
    fn process_own_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
    ) -> Result<Option<ActionRequired>, ControllerError> {
        match event_to_confirm.event_message.data.get_event_data() {
            // delegating event
            EventData::Icp(_) | EventData::Rot(_) | EventData::Ixn(_) => {
                self.source
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
                Ok(None)
            }
            // delegated event
            EventData::Dip(_) | EventData::Drt(_) => {
                self.source
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
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
    /// participants. If signing is required to finish the process it resturns
    /// proper notification.
    async fn process_group_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
        group_id: &IdentifierPrefix,
    ) -> Result<Option<ActionRequired>, ControllerError> {
        match event_to_confirm.event_message.data.get_event_data() {
            // delegating event
            EventData::Ixn(ixn) => {
                //| EventData::Rot(_) | EventData::Ixn(_) => {
                self.source
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
                if let Seal::Event(seal) = ixn.data[0].clone() {
                    let fully_signed_event = self
                        .source
                        .partially_witnessed_escrow
                        .get_event_by_sn_and_digest(seal.sn, &seal.prefix, &seal.event_digest);
                    if let Some(fully_signed) = fully_signed_event {
                        let witnesses = self.source.get_current_witness_list(&self.id)?;
                        self.source.publish(&witnesses, &fully_signed).await?;
                    };
                };
                Ok(None)
            }
            // delegated event
            EventData::Dip(_) | EventData::Drt(_) => {
                self.source
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
                let id = event_to_confirm.event_message.data.get_prefix();

                let seal = Seal::Event(EventSeal {
                    prefix: id,
                    sn: event_to_confirm.event_message.data.get_sn(),
                    event_digest: event_to_confirm.event_message.get_digest(),
                });

                let ixn = self.anchor_group(group_id, &[seal])?;
                let exn = event_generator::exchange(group_id, &ixn, ForwardTopic::Multisig)?;
                Ok(Some(ActionRequired::DelegationRequest(ixn, exn)))
            }
            _ => todo!(),
        }
    }
}
