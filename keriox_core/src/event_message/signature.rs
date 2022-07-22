use serde::{Deserialize, Serialize};

use crate::{
    event::sections::seal::EventSeal,
    prefix::{AttachedSignaturePrefix, BasicPrefix, IdentifierPrefix, SelfSigningPrefix},
};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Signature {
    Transferable(Option<EventSeal>, Vec<AttachedSignaturePrefix>),
    NonTransferable(BasicPrefix, SelfSigningPrefix),
}

impl Signature {
    pub fn get_signer(&self) -> Option<IdentifierPrefix> {
        match self {
            Signature::Transferable(seal, _) => seal.as_ref().map(|s| s.prefix.clone()),
            Signature::NonTransferable(id, _) => Some(IdentifierPrefix::Basic(id.clone())),
        }
    }
}
