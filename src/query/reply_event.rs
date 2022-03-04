use chrono::{DateTime, FixedOffset};
use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    event::{sections::seal::EventSeal, EventMessage, SerializationFormats},
    event_message::{
        dummy_event::DummyEventMessage, signature::Signature, Digestible, EventTypeTag, SaidEvent,
        Typeable,
    },
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
    state::IdentifierState,
};

use super::{key_state_notice::KeyStateNotice, Envelope, Route};

#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct ReplyData<D> {
    #[serde(rename = "a")]
    pub data: D,
}

pub type ReplyEvent<D> = SaidEvent<Envelope<ReplyData<D>>>;
pub type ReplyKsnEvent = ReplyEvent<KeyStateNotice>;
// pub type Reply = Envelope<ReplyData>;

impl<D: Serialize + Clone> ReplyEvent<D> {
    pub fn new_reply(
        ksn: D,
        route: Route,
        self_addressing: SelfAddressing,
        serialization: SerializationFormats,
    ) -> Result<EventMessage<ReplyEvent<D>>, Error> {
        let rpy_data = ReplyData { data: ksn };
        let env = Envelope::new(route, rpy_data);
        env.to_message(serialization, &self_addressing)
    }
}

impl<D: Serialize> ReplyEvent<D> {
    pub fn get_timestamp(&self) -> DateTime<FixedOffset> {
        self.content.timestamp
    }

    pub fn get_route(&self) -> Route {
        self.content.route.clone()
    }
}

impl ReplyEvent<KeyStateNotice> {
    pub fn get_prefix(&self) -> IdentifierPrefix {
        self.content.data.data.state.prefix.clone()
    }

    pub fn get_state(&self) -> IdentifierState {
        self.content.data.data.state.clone()
    }

    pub fn get_reply_data(&self) -> KeyStateNotice {
        self.content.data.data.clone()
    }
}

impl<D: Serialize + Clone> EventMessage<ReplyEvent<D>> {
    pub fn check_digest(&self) -> Result<(), Error> {
        let dummy = DummyEventMessage::dummy_event(
            self.event.clone(),
            self.serialization_info.kind,
            &self.event.get_digest().derivation,
        )?
        .serialize()?;
        self.event
            .get_digest()
            .verify_binding(&dummy)
            .then(|| ())
            .ok_or(Error::IncorrectDigest)
    }
}

#[cfg(feature = "query")]
pub fn bada_logic<D: Serialize + Clone>(
    new_rpy: &SignedReply<D>,
    old_rpy: &SignedReply<D>,
) -> Result<(), Error> {
    use std::cmp::Ordering;

    use crate::query::QueryError;

    // helper function for reply timestamps checking
    fn check_dts<D: Serialize>(
        new_rpy: &ReplyEvent<D>,
        old_rpy: &ReplyEvent<D>,
    ) -> Result<(), Error> {
        let new_dt = new_rpy.get_timestamp();
        let old_dt = old_rpy.get_timestamp();
        if new_dt >= old_dt {
            Ok(())
        } else {
            Err(QueryError::StaleRpy.into())
        }
    }
    match new_rpy.signature.clone() {
        Signature::Transferable(seal, _sigs) => {
            // A) If sn (sequence number) of last (if forked) Est evt that provides
            //  keys for signature(s) of new is greater than sn of last Est evt
            //  that provides keys for signature(s) of old.

            //  Or

            //  B) If sn of new equals sn of old And date-time-stamp of new is
            //     greater than old

            // check sns
            let new_sn = seal.sn;
            let old_sn: u64 = if let Signature::Transferable(ref seal, _) = old_rpy.signature {
                seal.sn
            } else {
                return Err(QueryError::Error(
                    "Improper signature type. Should be transferable.".into(),
                )
                .into());
            };

            match old_sn.cmp(&new_sn) {
                Ordering::Less => Ok(()),
                Ordering::Equal => check_dts(&new_rpy.reply.event, &old_rpy.reply.event),
                Ordering::Greater => Err(QueryError::StaleRpy.into()),
            }
        }
        Signature::NonTransferable(_bp, _sig) => {
            //  If date-time-stamp of new is greater than old
            check_dts(&new_rpy.reply.event, &old_rpy.reply.event)
        }
    }
}

impl<D> Typeable for ReplyData<D> {
    fn get_type(&self) -> EventTypeTag {
        EventTypeTag::Rpy
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SignedReply<D: Serialize + Clone> {
    pub reply: EventMessage<ReplyEvent<D>>,
    pub signature: Signature,
}

impl<D: Serialize + Clone> SignedReply<D> {
    pub fn new_nontrans(
        envelope: EventMessage<ReplyEvent<D>>,
        signer: BasicPrefix,
        signature: SelfSigningPrefix,
    ) -> Self {
        let signature = Signature::NonTransferable(signer, signature);
        Self {
            reply: envelope,
            signature,
        }
    }

    pub fn new_trans(
        envelope: EventMessage<ReplyEvent<D>>,
        signer_seal: EventSeal,
        signatures: Vec<AttachedSignaturePrefix>,
    ) -> Self {
        let signature = Signature::Transferable(signer_seal, signatures);
        Self {
            reply: envelope,
            signature,
        }
    }
}
