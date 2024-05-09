use keri_core::{
    actor::simple_controller::PossibleResponse, error, mailbox::MailboxResponse, oobi::{error::OobiError, Scheme}, prefix::{IdentifierPrefix, IndexedSignature, SelfSigningPrefix}, query::{
        mailbox::{MailboxQuery, MailboxRoute},
        query_event::SignedQuery,
    }, transport::TransportError
};

use crate::{
    communication::SendingError, mailbox_updating::ActionRequired,
};

use super::{broadcast::BroadcastingError, Identifier};

pub struct Mechanics {}

#[derive(Debug, thiserror::Error)]
pub enum MechanicsError {
    #[error(transparent)]
    SendingError(#[from] SendingError),

    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),

    #[error("Can't lock")]
    LockingError,

    #[error("transparent")]
    EventProcessingError(#[from] keri_core::error::Error),

    #[error(transparent)]
    ResponseProcessingError(#[from] ResponseProcessingError),

    #[error("No kel events for {0} saved")]
    UnknownIdentifierError(IdentifierPrefix),

    #[error("Can't generate event: {0}")]
    EventGenerationError(String),

    #[error("Not group participant")]
    NotGroupParticipantError,

    #[error("Error: {0}")]
    OtherError(String),

    #[error("Wrong event type")]
    WrongEventTypeError,

    #[error("Wrong event format")]
    EventFormatError,

    #[error("Inception event error: {0}")]
    InceptionError(String),

    #[error("Improper witness prefix, should be basic prefix")]
    WrongWitnessPrefixError,

    #[error("Oobi error: {0}")]
    OobiError(#[from] OobiError),

    #[error("Broadcasting error: {0}")]
    BroadcastingError(#[from] BroadcastingError)
}

#[derive(Debug, thiserror::Error)]
pub enum ResponseProcessingError {
    #[error("Unexpected response")]
    UnexpectedResponse,
    #[error("Error while processing receipts from response: {0}")]
    Receipts(keri_core::error::Error),
    #[error("Error while processing multisig from response: {0}")]
    Multisig(keri_core::error::Error),
    #[error("Error while processing delegate from response: {0}")]
    Delegate(keri_core::error::Error),
}

impl Identifier {
    /// Joins query events with their signatures, sends it to witness.
    pub async fn handle_management_query(
        &self,
        qry: &MailboxQuery,
        sig: SelfSigningPrefix,
    ) -> Result<PossibleResponse, SendingError> {
        let recipient = match &qry.data.data {
            MailboxRoute::Mbx {
                reply_route: _,
                args,
            } => Some(args.src.clone()),
        };

        let query = match &self.id {
            IdentifierPrefix::Basic(bp) => SignedQuery::new_nontrans(qry.clone(), bp.clone(), sig),
            _ => {
                let signatures = vec![IndexedSignature::new_both_same(sig, 0)];
                SignedQuery::new_trans(qry.clone(), self.id().clone(), signatures)
            }
        };
        self.communication
            .send_management_query_to(recipient.as_ref().unwrap(), Scheme::Http, query)
            .await
    }

    /// Joins query events with their signatures, sends it to witness and
    /// process its response. If user action is needed to finalize process,
    /// returns proper notification.
    pub async fn finalize_mechanics_query(
        &mut self,
        queries: Vec<(MailboxQuery, SelfSigningPrefix)>,
    ) -> Result<Vec<ActionRequired>, MechanicsError> {
        let mut actions = Vec::new();
        for (qry, sig) in queries {
            let args = qry.get_args();
            let (recipient, about_who, from_who) =
                (args.src.clone(), Some(&args.i), Some(&args.pre));
            match self.handle_management_query(&qry, sig).await? {
                PossibleResponse::Mbx(mbx) => {
                    // only process if we actually asked about mailbox
                    if let (Some(from_who), Some(about_who)) =
                        (from_who.as_ref(), about_who.as_ref())
                    {
                        actions.append(
                            &mut self
                                .mailbox_response(&recipient, from_who, about_who, &mbx)
                                .await?,
                        );
                        let witnesses = self
                            .witnesses()
                            .map(|bp| IdentifierPrefix::Basic(bp))
                            .collect::<Vec<_>>();
                        self.broadcast_receipts(&witnesses).await?;
                    }
                }
                _ => panic!("Unexpected response"),
            };
        }

        Ok(actions)
    }

    pub async fn mailbox_response(
        &self,
        recipient: &IdentifierPrefix,
        from_who: &IdentifierPrefix,
        about_who: &IdentifierPrefix,
        res: &MailboxResponse,
    ) -> Result<Vec<ActionRequired>, MechanicsError> {
        let req = if from_who == about_who {
            // process own mailbox
            let req = self.process_own_mailbox(res)?;
            self.query_cache
                .update_last_asked_index(recipient.clone(), res)?;
            req
        } else {
            // process group mailbox
            let group_req = self.process_group_mailbox(res, about_who).await?;
            self.query_cache
                .update_last_asked_group_index(recipient.clone(), res)?;
            group_req
        };
        Ok(req)
    }
}
