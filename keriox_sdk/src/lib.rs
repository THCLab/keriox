//! # keri-sdk
//!
//! Self-certifying digital identities with verifiable key rotation — no
//! blockchain, no central registry — based on [KERI] (Key Event Receipt
//! Infrastructure).
//!
//! [KERI]: https://keri.one
//!
//! ## Five-minute tour
//!
//! Everything starts with a [`Keri`] store:
//!
//! ```
//! # tokio_test::block_on(async {
//! use keri_sdk::Keri;
//!
//! # let dir = tempfile::tempdir().unwrap();
//! # let path = dir.path();
//! let keri = Keri::open(path)?;
//!
//! // Create an identity (add .witness("http://...") for real deployments).
//! let alice = keri.new_identity("alice").build().await?;
//!
//! // Sign — the result is a self-contained string.
//! let signed = alice.sign(b"hello world").await?;
//!
//! // Verify — returns the payload and the proven signer.
//! let verified = keri.verify(signed.as_cesr())?;
//! assert_eq!(verified.payload, b"hello world");
//! assert_eq!(&verified.signer, alice.id());
//!
//! // Rotate keys — old signatures stay verifiable, new ones use new keys.
//! alice.rotate().await?;
//! # Ok::<(), keri_sdk::Error>(())
//! # }).unwrap();
//! ```
//!
//! Verifying someone else's signature requires knowing their key history:
//! they share their OOBI URL ([`Identity::oobi_url`]) or raw key history
//! ([`Identity::kel`]), and you import it once with
//! [`Keri::import_contact`].
//!
//! Credentials ([`Identity::issue`]) are ACDC 2.0 documents, each with a
//! registry of its own whose blinded state the issuer anchors. The holder
//! presents the credential with its registry, and a verifier judges the
//! presentation against the issuer's key history
//! ([`Keri::verify_credential`], [`Identity::revoke`]).
//!
//! Multi-party flows — delegation ([`IdentityBuilder::delegated_by`]) and
//! group identities ([`Identity::new_group`]) — are modeled as a small
//! number of explicit steps: each produces messages ([`Outgoing`]) the
//! application delivers to the other party, who takes them with
//! [`Identity::receive`].
//!
//! The `tests/e2e_*.rs` files in the repository are narrated, runnable
//! walkthroughs of every flow above.
//!
//! New to KERI? Read [`concepts`] — every protocol term used in these docs
//! (witness, OOBI, registry, …) explained in plain language. For a
//! task-oriented index ("I want to X → call Y"), see `docs/cookbook.md` in
//! the repository.
//!
//! ## Layers
//!
//! | Layer | For |
//! |-------|-----|
//! | crate root ([`Keri`], [`Identity`], …) | most applications |
//! | [`advanced`] | custom flows, weighted thresholds, out-of-band transports, CESR tooling |

#![warn(missing_docs)]

// The mid-level layer is documented at module granularity; per-item docs
// are being filled in progressively and should not fail the facade's
// documentation lint.
#[allow(missing_docs)]
pub mod advanced;

mod contact;
mod credential;
mod delivery;
mod error;
mod group;
mod identity;
mod ids;
mod keri;
mod message;
mod requests;
mod retry;

#[doc = include_str!("../docs/concepts.md")]
pub mod concepts {}

pub use credential::{Credential, CredentialStatus, ReceivedCredential};
pub use delivery::Outgoing;
pub use error::{Error, Result};
pub use group::{Group, GroupBuilder, GroupInvite, GroupRequest};
pub use identity::{Identity, IdentityBackup, IdentityBuilder, KeyAlgorithm};
pub use ids::{CredentialId, IdentityId};
pub use keri::Keri;
pub use message::{SignedMessage, Verified};
pub use requests::{DelegationApproval, DelegationHandle, PendingRequest};
pub use retry::RetryPolicy;

pub use advanced::types::StorageConfig;

/// ACDC 2.0, re-exported to build and read credentials with the version
/// keri-sdk uses.
pub use acdc;
/// Registry policy and verdicts, for [`Keri::verify_credential_with`].
pub use teliox::registry::{AbandonedIssuer, Policy};

/// The key provider interface, re-exported so that applications depend on
/// keri-sdk alone and always get the version keri-sdk is built with.
#[cfg(feature = "keyprovider")]
pub use keri_keyprovider as keyprovider;
#[cfg(feature = "keyprovider")]
pub use keri_keyprovider::{
    KeyProvider, KeyProviderError, KeyProviderFactory, PublicKeyData, SignatureAlgorithm,
};
