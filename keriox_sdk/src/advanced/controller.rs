use std::path::PathBuf;

use keri_controller::{
    config::ControllerConfig, controller::RedbController, IdentifierPrefix, SelfSigningPrefix,
};
use keri_core::{event_message::signed_event_message::Message, state::IdentifierState};

use crate::advanced::identifier::IdentifierInner;
use crate::advanced::{error::Result, Identifier};

/// The storage-specific controller this wrapper dispatches to.
pub(crate) enum ControllerInner {
    Redb(RedbController),
    #[cfg(feature = "storage-postgres")]
    Postgres(keri_controller::controller::PostgresController),
}

/// Run the same expression against whichever backend controller is inside —
/// the generic `keri_controller::controller::Controller<D, T, S>` has one
/// set of methods and fields for every backend.
macro_rules! dispatch {
    ($self:expr, $i:ident => $body:expr) => {
        match &$self.inner {
            ControllerInner::Redb($i) => $body,
            #[cfg(feature = "storage-postgres")]
            ControllerInner::Postgres($i) => $body,
        }
    };
}

/// Concrete controller wrapping the storage-specific
/// `keri_controller::controller::Controller` (redb or Postgres backed).
pub struct Controller {
    pub(crate) inner: ControllerInner,
}

impl Controller {
    /// Create a controller with a database at the given path, using default transport.
    pub fn new(db_path: PathBuf) -> Result<Self> {
        let config = ControllerConfig {
            db_path,
            ..ControllerConfig::default()
        };
        Ok(Self {
            inner: ControllerInner::Redb(RedbController::new(config)?),
        })
    }

    /// Create a controller whose event databases live in Postgres.
    ///
    /// `db_path` still hosts the small redb file for the mailbox query
    /// cache (read positions are local, per-process state).
    #[cfg(feature = "storage-postgres")]
    pub async fn new_postgres(db_path: PathBuf, database_url: &str) -> Result<Self> {
        let config = ControllerConfig {
            db_path,
            ..ControllerConfig::default()
        };
        Ok(Self {
            inner: ControllerInner::Postgres(
                keri_controller::controller::PostgresController::new_postgres(
                    database_url,
                    config,
                )
                .await?,
            ),
        })
    }

    /// Create a controller with the chosen storage backend.
    ///
    /// With [`StorageConfig::Redb`](crate::advanced::types::StorageConfig::Redb)
    /// this is [`Controller::new`]; with
    /// [`StorageConfig::InMemory`](crate::advanced::types::StorageConfig::InMemory)
    /// every database (KEL, TEL, OOBIs, escrows, query cache) uses redb's
    /// in-memory backend — `db_path` is ignored and nothing is written to it.
    /// With `StorageConfig::Postgres` the event databases live in Postgres
    /// (construction blocks on the connection; use `Controller::new_postgres`
    /// from async contexts).
    pub fn new_with_storage(
        db_path: PathBuf,
        storage: &crate::advanced::types::StorageConfig,
    ) -> Result<Self> {
        use crate::advanced::types::StorageConfig;
        match storage {
            StorageConfig::Redb => Self::new(db_path),
            StorageConfig::InMemory => Ok(Self {
                inner: ControllerInner::Redb(RedbController::new_in_memory(
                    ControllerConfig::default(),
                )?),
            }),
            #[cfg(feature = "storage-postgres")]
            StorageConfig::Postgres { url } => {
                // sqlx in this workspace runs on async-std, which drives its
                // I/O on its own reactor threads — blocking the calling
                // thread here is safe even inside a tokio runtime.
                async_std::task::block_on(Self::new_postgres(db_path, url))
            }
        }
    }

    /// Create a controller from a full `ControllerConfig`.
    pub fn new_with_config(config: ControllerConfig) -> Result<Self> {
        Ok(Self {
            inner: ControllerInner::Redb(RedbController::new(config)?),
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
        dispatch!(self, i => Ok(i
            .incept(public_keys, next_pub_keys, witnesses, witness_threshold)
            .await?))
    }

    /// Finalize inception by attaching a signature, returning the resulting `Identifier`.
    pub fn finalize_incept(&self, event: &[u8], sig: &SelfSigningPrefix) -> Result<Identifier> {
        match &self.inner {
            ControllerInner::Redb(c) => Ok(Identifier {
                inner: IdentifierInner::Redb(c.finalize_incept(event, sig)?),
            }),
            #[cfg(feature = "storage-postgres")]
            ControllerInner::Postgres(c) => Ok(Identifier {
                inner: IdentifierInner::Postgres(c.finalize_incept(event, sig)?),
            }),
        }
    }

    /// Return the accepted KEL (with receipts) for any known identifier.
    pub fn get_kel_with_receipts(
        &self,
        id: &IdentifierPrefix,
    ) -> Option<Vec<keri_core::event_message::signed_event_message::Notice>> {
        dispatch!(self, i => i.get_kel_with_receipts(id))
    }

    /// Verify a signature over data using known KEL state.
    pub fn verify(
        &self,
        data: &[u8],
        signature: &keri_core::event_message::signature::Signature,
    ) -> std::result::Result<(), keri_core::processor::validator::VerificationError> {
        dispatch!(self, i => i.verify(data, signature))
    }

    /// Return the accepted `IdentifierState` for a known identifier.
    pub fn find_state(&self, id: &IdentifierPrefix) -> Result<IdentifierState> {
        dispatch!(self, i => Ok(i.find_state(id)?))
    }

    /// Process a single KEL message (notice, reply, etc.).
    pub fn process(&self, msg: &Message) -> Result<()> {
        dispatch!(self, i => i
            .known_events
            .process(msg)
            .map(|_| ())
            .map_err(|e| crate::advanced::Error::Other(e.to_string())))
    }

    /// Parse and process a KEL event stream from raw CESR bytes.
    ///
    /// Each message in the stream (events, receipts, replies) is processed
    /// into the local database. Use together with
    /// [`crate::advanced::ephemeral::EphemeralIdentifier::pull_kel`] to import an
    /// identifier's KEL fetched from a witness.
    pub fn process_kel_stream(&self, stream: &[u8]) -> Result<()> {
        let messages = keri_core::actor::parse_event_stream(stream)
            .map_err(|e| crate::advanced::Error::CesrParseError(e.to_string()))?;
        for message in &messages {
            self.process(message)?;
        }
        Ok(())
    }

    /// Parse and process a TEL event stream from raw bytes.
    pub fn process_tel_stream(&self, stream: &[u8]) -> Result<()> {
        dispatch!(self, i => i
            .known_events
            .tel
            .parse_and_process_tel_stream(stream)
            .map_err(|e| crate::advanced::Error::Other(e.to_string())))
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
        match &self.inner {
            ControllerInner::Redb(c) => Identifier {
                inner: IdentifierInner::Redb(keri_controller::controller::RedbIdentifier::new(
                    id,
                    registry_id,
                    c.known_events.clone(),
                    c.communication.clone(),
                    c.cache.clone(),
                )),
            },
            #[cfg(feature = "storage-postgres")]
            ControllerInner::Postgres(c) => Identifier {
                inner: IdentifierInner::Postgres(
                    keri_controller::controller::PostgresIdentifier::new(
                        id,
                        registry_id,
                        c.known_events.clone(),
                        c.communication.clone(),
                        c.cache.clone(),
                    ),
                ),
            },
        }
    }
}
