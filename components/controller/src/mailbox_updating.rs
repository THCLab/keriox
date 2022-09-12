use keri::{
    actor::{event_generator, prelude::Message},
    event::sections::seal::{EventSeal, Seal},
    event_message::{
        exchange::ForwardTopic,
        signed_event_message::{Notice, SignedEventMessage, SignedNontransferableReceipt},
    },
    prefix::IdentifierPrefix,
    query::query_event::MailboxResponse,
};

use super::{error::ControllerError, identifier_controller::IdentifierController};

use keri::{
    event::EventMessage,
    event_message::{exchange::ExchangeMessage, key_event_message::KeyEvent},
};

pub enum ActionRequired {
    MultisigRequest(EventMessage<KeyEvent>, ExchangeMessage),
    DelegationRequest(EventMessage<KeyEvent>, ExchangeMessage),
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
        mb.multisig
            .iter()
            .map(|event| self.process_own_multisig(event))
            .chain(
                mb.delegate
                    .iter()
                    .map(|del_event| self.process_own_delegate(del_event)),
            )
            .collect::<Result<Vec<_>, ControllerError>>()
    }

    pub fn process_group_mailbox(
        &self,
        mb: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, ControllerError> {
        mb.multisig
            .iter()
            .try_for_each(|event| self.process_group_multisig(event))?;

        mb.multisig
            .iter()
            .map(|del_event| self.process_own_delegate(del_event))
            .collect::<Result<Vec<_>, ControllerError>>()
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
        let receipient = event.event.get_prefix();
        // Construct exn message (will be stored in group identidfier mailbox)
        let exn = event_generator::exchange(&receipient, &event, ForwardTopic::Multisig)?;
        Ok(ActionRequired::MultisigRequest(event, exn))
    }

    /// If leader and event is fully signed, return event to forward to witness.
    fn process_group_multisig(&self, event: &SignedEventMessage) -> Result<(), ControllerError> {
        self.source
            .process(&Message::Notice(Notice::Event(event.clone())))?;

        let id = event.event_message.event.get_prefix();
        let fully_signed_event = self
            .source
            .partially_witnessed_escrow
            .get_event_by_sn_and_digest(
                event.event_message.event.get_sn(),
                &id,
                &event.event_message.get_digest(),
            );

        let own_index = self.get_index(&event.event_message.event)?;
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
                let witnesses = self.source.get_current_witness_list(&id)?;
                self.source.publish(&witnesses, &to_publish)
            }
            None => Ok(()),
        }
    }

    /// Create delegating event, pack it in exn message (delegate topic).
    fn process_own_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
    ) -> Result<ActionRequired, ControllerError> {
        self.source
            .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
        let id = event_to_confirm.event_message.event.get_prefix();

        let seal = Seal::Event(EventSeal {
            prefix: id.clone(),
            sn: event_to_confirm.event_message.event.get_sn(),
            event_digest: event_to_confirm.event_message.get_digest(),
        });

        let ixn = self.anchor_with_seal(&vec![seal])?;
        let exn = event_generator::exchange(&id, &ixn, ForwardTopic::Delegate)?;
        Ok(ActionRequired::DelegationRequest(ixn, exn))
    }

    /// Create delegating event, pack it in exn message to group identifier (multisig topic).
    fn process_group_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
        group_id: &IdentifierPrefix,
    ) -> Result<ActionRequired, ControllerError> {
        self.source
            .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))?;
        let id = event_to_confirm.event_message.event.get_prefix();

        let seal = Seal::Event(EventSeal {
            prefix: id.clone(),
            sn: event_to_confirm.event_message.event.get_sn(),
            event_digest: event_to_confirm.event_message.get_digest(),
        });

        let ixn = self.anchor_group(group_id, &vec![seal])?;
        let exn = event_generator::exchange(&group_id, &ixn, ForwardTopic::Multisig)?;
        Ok(ActionRequired::DelegationRequest(ixn, exn))
    }
}
