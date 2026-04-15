use std::path::PathBuf;

use keri_controller::{
    config::ControllerConfig,
    controller::RedbController,
    IdentifierPrefix, SelfSigningPrefix,
};
use keri_core::state::IdentifierState;

use crate::{error::Result, Identifier};

/// Concrete controller wrapping `keri_controller::controller::RedbController`.
pub struct Controller {
    pub(crate) inner: RedbController,
}

impl Controller {
    /// Create a controller with a database at the given path, using default transport.
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let config = ControllerConfig {
            db_path,
            ..ControllerConfig::default()
        };
        Ok(Self {
            inner: RedbController::new(config)?,
        })
    }

    /// Create a controller from a full `ControllerConfig`.
    pub fn new_with_config(config: ControllerConfig) -> Result<Self> {
        Ok(Self {
            inner: RedbController::new(config)?,
        })
    }

    /// Generate an inception event (CESR-encoded JSON string).
    pub async fn incept(
        &self,
        public_keys: Vec<keri_controller::BasicPrefix>,
        next_pub_keys: Vec<keri_controller::BasicPrefix>,
        witnesses: Vec<keri_controller::LocationScheme>,
        witness_threshold: u64,
    ) -> Result<String> {
        Ok(self
            .inner
            .incept(public_keys, next_pub_keys, witnesses, witness_threshold)
            .await?)
    }

    /// Finalize inception by attaching a signature, returning the resulting `Identifier`.
    pub fn finalize_incept(
        &self,
        event: &[u8],
        sig: &SelfSigningPrefix,
    ) -> Result<Identifier> {
        let inner_id = self.inner.finalize_incept(event, sig)?;
        Ok(Identifier { inner: inner_id })
    }

    /// Return the accepted KEL (with receipts) for any known identifier.
    pub fn get_kel_with_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<Vec<keri_core::event_message::signed_event_message::Notice>> {
        self.inner.get_kel_with_receipts(id)
    }

    /// Verify a signature over data using known KEL state.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &keri_core::event_message::signature::Signature,
    ) -> std::result::Result<(), keri_core::processor::validator::VerificationError> {
        self.inner.verify(data, signature)
    }

    /// Return the accepted `IdentifierState` for a known identifier.
    pub fn find_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState> {
        Ok(self.inner.find_state(id)?)
    }

    /// Reconstruct an `Identifier` from a known prefix and optional registry.
    ///
    /// Use this to load an identifier whose database already exists at the
    /// controller's `db_path`.
    pub fn load_identifier(
        &self,
        id: IdentifierPrefix,
        registry_id: Option<IdentifierPrefix>,
    ) -> Identifier {
        use keri_controller::controller::RedbIdentifier;
        Identifier {
            inner: RedbIdentifier::new(
                id,
                registry_id,
                self.inner.known_events.clone(),
                self.inner.communication.clone(),
                #[cfg(feature = "query_cache")]
                self.inner.cache.clone(),
            ),
        }
    }
}
