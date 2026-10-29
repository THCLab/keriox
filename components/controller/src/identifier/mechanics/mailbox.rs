use keri_core::{
    actor::event_generator,
    database::{EscrowCreator, EventDatabase},
    event::{
        event_data::EventData,
        sections::seal::{EventSeal, Seal},
    },
    event_message::{
        signed_event_message::{Message, Notice, SignedEventMessage},
        EventTypeTag,
    },
    mailbox::exchange::ForwardTopic,
    oobi_manager::storage::OobiStorageBackend,
    prefix::IdentifierPrefix,
};
use teliox::registry::RegistryStore;

use crate::{identifier::Identifier, mailbox_updating::ActionRequired};

use super::{forwards::ResponseProcessingError, MechanicsError};

impl<D, T, S> Identifier<D, T, S>
where
    D: EventDatabase + EscrowCreator + Send + Sync + 'static,
    T: RegistryStore + Send + Sync + 'static,
    S: OobiStorageBackend,
{
    /// Returns exn message that contains signed multisig event and will be
    /// forward to group identifier's mailbox.
    pub(super) fn process_own_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<ActionRequired, MechanicsError> {
        self.known_events
            .process(&Message::Notice(Notice::Event(event.clone())))
            .map_err(ResponseProcessingError::Multisig)?;
        let event = event.event_message.clone();
        let recipient = event.data.get_prefix();
        // Construct exn message (will be stored in group identifier mailbox)
        let exn = event_generator::exchange(
            &self.id,
            &recipient,
            &event,
            ForwardTopic::Multisig,
        );
        Ok(ActionRequired::MultisigRequest(event, exn))
    }

    /// If leader and event is fully signed publish event to witness.
    pub(super) async fn process_group_multisig(
        &self,
        event: &SignedEventMessage,
    ) -> Result<Option<ActionRequired>, MechanicsError> {
        self.known_events
            .process(&Message::Notice(Notice::Event(event.clone())))
            .map_err(ResponseProcessingError::Multisig)?;
        self.publish(&event).await?;
        match &event.event_message.data.event_data {
            EventData::Icp(_inception_event) => Ok(None),
            _ => {
                let event_message = event.event_message.clone();
                let recipient = event_message.data.get_prefix();
                // Construct exn message (will be stored in group identifier mailbox)
                let exn =
                    event_generator::exchange(
                        &self.id,
                        &recipient,
                        &event_message,
                        ForwardTopic::Multisig,
                    );
                Ok(Some(ActionRequired::MultisigRequest(event_message, exn)))
            }
        }
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
            )
            .map_err(|_e| {
                MechanicsError::OtherError("Partially signed database error".to_string())
            })?;

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
    pub(super) fn process_own_delegate(
        &self,
        event_to_confirm: &SignedEventMessage,
    ) -> Result<Option<ActionRequired>, MechanicsError> {
        // Dispatch on the type tag: a parsed `drt` carries the same data as
        // a `rot`, so only the tag tells a delegated rotation apart.
        match event_to_confirm.event_message.event_type {
            // delegated event
            EventTypeTag::Dip | EventTypeTag::Drt => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                let (delegating_event, exn) = self.delegate(&event_to_confirm.event_message)?;
                Ok(Some(ActionRequired::DelegationRequest(
                    delegating_event,
                    exn,
                )))
            }
            // delegating event
            _ => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                Ok(None)
            }
        }
    }

    /// Process event from group delegate mailbox. Creates group delegating
    /// event and send it to group multisig mailbox for other group
    /// participants. If signing is required to finish the process it returns
    /// proper notification.
    pub(super) async fn process_group_delegate(
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
                        .get_event_by_sn_and_digest(seal.sn, &seal.prefix, &seal.event_digest())
                        .map_err(|_e| {
                            MechanicsError::OtherError(
                                "Partially signed database error".to_string(),
                            )
                        })?;
                    if let Some(fully_signed) = fully_signed_event {
                        let witnesses = self.known_events.get_current_witness_list(&self.id)?;
                        self.communication.publish(witnesses, &fully_signed).await?;
                    };
                };
                Ok(None)
            }
            // delegated event; a parsed `drt` carries `rot` data, so check
            // the type tag
            _ if matches!(
                event_to_confirm.event_message.event_type,
                EventTypeTag::Dip | EventTypeTag::Drt
            ) =>
            {
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
                let exn = event_generator::exchange(
                    &self.id,
                    group_id,
                    &ixn,
                    ForwardTopic::Multisig,
                );
                // let (delegating_event, exn) = self.delegate(&event_to_confirm.event_message)?;
                Ok(Some(ActionRequired::DelegationRequest(ixn, exn)))
            }
            // nothing to delegate; process it like any key event, as
            // process_own_delegate does
            _ => {
                self.known_events
                    .process(&Message::Notice(Notice::Event(event_to_confirm.clone())))
                    .map_err(ResponseProcessingError::Delegate)?;
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use keri_core::{
        event_message::signed_event_message::{Message, Notice},
        prefix::{BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
        signer::{CryptoBox, KeyManager},
    };
    use tempfile::Builder;

    use crate::{config::ControllerConfig, RedbController, RedbIdentifier};

    fn identifier(prefix: &str) -> (tempfile::TempDir, RedbController, RedbIdentifier) {
        let root = Builder::new().prefix(prefix).tempdir().unwrap();
        let controller = RedbController::new(ControllerConfig {
            db_path: root.path().to_owned(),
            ..Default::default()
        })
        .unwrap();
        let km = CryptoBox::new().unwrap();
        let icp = futures::executor::block_on(controller.incept(
            vec![BasicPrefix::Ed25519(km.public_key())],
            vec![BasicPrefix::Ed25519(km.next_public_key())],
            vec![],
            0,
        ))
        .unwrap();
        let sig = SelfSigningPrefix::Ed25519Sha512(km.sign(icp.as_bytes()).unwrap());
        let id = controller.finalize_incept(icp.as_bytes(), &sig).unwrap();
        (root, controller, id)
    }

    /// A delegation forward for a group carries a delegating or a delegated
    /// event; anything else is processed like any key event instead of
    /// panicking.
    #[async_std::test]
    async fn a_group_delegation_forward_of_another_type_is_processed() {
        let (_root, _controller, member) = identifier("grp-del-member");
        let (_other_root, _other_controller, other) = identifier("grp-del-other");
        let Some(Notice::Event(icp)) = other.get_own_kel().unwrap().into_iter().next() else {
            panic!("an inception is the first event of a KEL")
        };
        let group =
            IdentifierPrefix::Basic(BasicPrefix::Ed25519(CryptoBox::new().unwrap().public_key()));
        let action = member.process_group_delegate(&icp, &group).await.unwrap();

        assert!(action.is_none());
        assert!(member.find_state(other.id()).is_ok());
    }

    /// Forwards reach a controller through receive_forwards. One that turns
    /// up among other messages, e.g. in a watcher's answer, is refused.
    #[test]
    fn an_exchange_message_is_refused_by_process() {
        let (_root, controller, _id) = identifier("exn-process");
        let exn = br#"{"v":"KERICAACAAJSONAAGJ.","t":"exn","d":"EJ7fardNHewIxRFQxO0QrzawpYRHh3jhfTjQ2FuAmC8E","i":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","ri":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","x":"","p":"","dt":"2024-01-01T00:00:00.000000+00:00","r":"/fwd","q":{"pre":"EJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD","topic":"multisig"},"a":{"evt":"EML-lfYS2KNY1hGN5nzjUbBTBkOHqKw6MbNEyJFMPHgn"}}-CCt-XAuEJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pDMAAAEJ_XPdN9hbhbblm5JuU3y45viXKOTZqbMxD3hEggp0pD-KAWAACYHV0RI_0YMPa7JwhDHMtcVlSj8UonfXMQ_EFFjoMVJEQXa5r2bJoMPl7VjeRtJXmvTI_4i9XTcMdVVhaZu0IN-BB9-HBl5BBkAHsidiI6IktFUkkxMEpTT04wMDAxMmJfIiwidCI6ImljcCIsImQiOiJFSl9YUGROOWhiaGJibG01SnVVM3k0NXZpWEtPVFpxYk14RDNoRWdncDBwRCIsImkiOiJFSl9YUGROOWhiaGJibG01SnVVM3k0NXZpWEtPVFpxYk14RDNoRWdncDBwRCIsInMiOiIwIiwia3QiOiIxIiwiayI6WyJERWJiR01KMFVyWlBCYlpDZ2pVSFB2bEJLUEtWLXMwa3NPWklSb0ZGOGNnNSJdLCJudCI6IjEiLCJuIjpbIkVGVk9RMEZILTRnSldvYnlXYVdla2R2eTh2VXlNVEtIYUEzZ0ZZbkJYdDBRIl0sImJ0IjoiMCIsImIiOltdLCJjIjpbXSwiYSI6W119-KAWAACj84Cf9s2C6cTNd4Rv5bSWbj4fJRdOgg82yf0A_PkUTMjNYUc40-3HxMNx3fhsDEhsKR1Br1YWhtI-pfgS-oIE"#;
        let msg = Message::try_from(
            keri_core::event_message::cesr_adapter::parse_cesr_stream(exn).unwrap(),
        )
        .unwrap();

        assert!(controller.known_events.process(&msg).is_err());
    }
}
