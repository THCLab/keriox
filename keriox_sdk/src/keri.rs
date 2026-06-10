//! The [`Keri`] root object — the single entry point of the high-level API.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::advanced::store::KeriStore;
use crate::advanced::types::VerificationIssue;
use crate::credential::CredentialStatus;
use crate::error::{Error, Result};
use crate::identity::{Identity, IdentityBuilder, Keys};
use crate::ids::{CredentialId, IdentityId};
use crate::message::{signer_of, Verified};
use crate::retry::RetryPolicy;

/// Shared state behind [`Keri`] and every [`Identity`] handle.
pub(crate) struct KeriInner {
    pub(crate) store: KeriStore,
    pub(crate) root: PathBuf,
    pub(crate) retry: RetryPolicy,
}

impl KeriInner {
    pub(crate) fn alias_exists(&self, alias: &str) -> bool {
        self.root.join(alias).join("id").is_file()
    }
}

/// Your KERI store: identities you control and contacts you can verify.
///
/// One `Keri` instance manages one directory on disk. Open it once at
/// startup and share it (it is cheap to clone) across your application.
///
/// ```no_run
/// # async fn example() -> keri_sdk::Result<()> {
/// use keri_sdk::Keri;
///
/// let keri = Keri::open("~/.myapp/keri")?;
/// let alice = keri.new_identity("alice")
///     .witness("http://witness.example:3232")
///     .build().await?;
///
/// let signed = alice.sign(b"hello world").await?;
/// let verified = keri.verify(signed.as_cesr())?;
/// assert_eq!(verified.payload, b"hello world");
/// # Ok(()) }
/// ```
#[derive(Clone)]
pub struct Keri {
    inner: Arc<KeriInner>,
}

impl Keri {
    /// Open (or create) a store at `path`. A leading `~/` expands to the
    /// user's home directory.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with(path, RetryPolicy::default())
    }

    /// Like [`Keri::open`], with a custom [`RetryPolicy`] for network
    /// operations.
    pub fn open_with(path: impl AsRef<Path>, retry: RetryPolicy) -> Result<Self> {
        let root = expand_home(path.as_ref());
        let store = KeriStore::open(root.clone())?;
        Ok(Keri {
            inner: Arc::new(KeriInner { store, root, retry }),
        })
    }

    /// Start creating a new identity stored under `alias`.
    ///
    /// Returns a builder; call `.build().await` to finish:
    ///
    /// ```no_run
    /// # async fn example(keri: keri_sdk::Keri) -> keri_sdk::Result<()> {
    /// let alice = keri.new_identity("alice")
    ///     .witness("http://witness.example:3232")
    ///     .build().await?;
    /// # Ok(()) }
    /// ```
    pub fn new_identity(&self, alias: &str) -> IdentityBuilder {
        IdentityBuilder::new(self.inner.clone(), alias)
    }

    /// Load an identity previously created in this store.
    pub fn identity(&self, alias: &str) -> Result<Identity> {
        if !self.inner.alias_exists(alias) {
            return Err(Error::IdentityNotFound(alias.to_string()));
        }
        let identifier = self.inner.store.load(alias)?;
        Ok(Identity {
            id: IdentityId::from(identifier.id().clone()),
            keri: self.inner.clone(),
            alias: alias.to_string(),
            keys: Keys::Software,
        })
    }

    /// Load an identity whose keys live in external key providers (created
    /// with [`IdentityBuilder::key_providers`]). The SDK stores no key
    /// material for such identities, so the application supplies the same
    /// providers again.
    #[cfg(feature = "keyprovider")]
    pub fn identity_with_providers(
        &self,
        alias: &str,
        current: Arc<dyn keri_keyprovider::KeyProvider>,
        next: Arc<dyn keri_keyprovider::KeyProvider>,
    ) -> Result<Identity> {
        if !self.inner.alias_exists(alias) {
            return Err(Error::IdentityNotFound(alias.to_string()));
        }
        let identifier = self.inner.store.load(alias)?;
        Ok(Identity {
            id: IdentityId::from(identifier.id().clone()),
            keri: self.inner.clone(),
            alias: alias.to_string(),
            keys: Keys::Provider {
                current: crate::advanced::keyprovider_adapter::KeriSigner::Provider(current),
                next,
            },
        })
    }

    /// List the aliases of all identities in this store.
    pub fn identities(&self) -> Result<Vec<String>> {
        Ok(self
            .inner
            .store
            .list_aliases()?
            .into_iter()
            .filter(|a| !a.starts_with('.') && self.inner.alias_exists(a))
            .collect())
    }

    /// Verify a signed message and return its payload and proven signer.
    ///
    /// Verification is local: it checks the signature against key histories
    /// already known to this store (your own identities and imported
    /// contacts) and performs **no network calls**. If the signer is not
    /// known yet, this fails with [`Error::UnknownSigner`] — import them
    /// first with [`Keri::import_contact`].
    pub fn verify(&self, cesr: &str) -> Result<Verified> {
        let bytes = cesr.as_bytes();
        let claimed = signer_of(bytes)?;

        let mut candidates = self.identities()?;
        // The contacts database (imported foreign identities) is checked too,
        // once it exists (created by import_contact).
        candidates.extend(self.contact_aliases());

        let mut saw_invalid_signature = false;
        for alias in candidates {
            let Ok(identifier) = self.inner.store.load(&alias) else {
                continue;
            };
            match identifier.verify_from_cesr_detailed(bytes) {
                Ok(()) => {
                    let verified = crate::advanced::signing::verify(&identifier, bytes)?;
                    return Ok(Verified {
                        payload: verified.payload,
                        signer: IdentityId::from(verified.signer_id),
                    });
                }
                Err(issues) => {
                    if issues
                        .iter()
                        .any(|i| matches!(i, VerificationIssue::SignatureInvalid))
                    {
                        saw_invalid_signature = true;
                    }
                    // Unknown signer / missing events here just mean this
                    // particular database has not seen the signer — try the
                    // next one.
                }
            }
        }

        if saw_invalid_signature {
            Err(Error::InvalidSignature { claimed })
        } else {
            Err(Error::UnknownSigner { id: claimed })
        }
    }

    /// Import another party's identity so their signatures can be verified.
    ///
    /// Accepts what the other party shared with you:
    /// - their **OOBI URL** (from [`crate::Identity::oobi_url`]) — their key
    ///   history is fetched from the witness in the URL, or
    /// - their **key history** itself (the CESR string from
    ///   [`crate::Identity::kel`]) — fully offline.
    ///
    /// Returns the imported identity's id. Importing again later picks up
    /// any key rotations they made in the meantime.
    pub async fn import_contact(&self, source: &str) -> Result<IdentityId> {
        let trimmed = source.trim();

        // A key-history (KEL) CESR stream starts with a KERI event JSON.
        if trimmed.starts_with('{') {
            let aid = first_event_identifier(trimmed.as_bytes())?;
            return self.ingest_contact_kel(&aid, trimmed.as_bytes());
        }

        // An OOBI URL: …/oobi/<their id>[/witness/<witness id>]
        if let Ok(url) = url::Url::parse(trimmed) {
            let segments: Vec<&str> = url
                .path_segments()
                .map(|s| s.collect())
                .unwrap_or_default();
            if let Some(pos) = segments.iter().position(|s| *s == "oobi") {
                if let Some(cid) = segments.get(pos + 1) {
                    let id: IdentityId = cid.parse()?;
                    let mut base = url.clone();
                    base.set_path("");
                    base.set_query(None);
                    return self.import_contact_from(&id, base.as_str()).await;
                }
            }
            return Err(Error::InvalidInput {
                expected: "OOBI URL containing /oobi/<identifier>",
                cause: format!(
                    "cannot tell whose history to fetch from {trimmed}; if you only have a \
                     witness base URL, use import_contact_from(id, witness_url)"
                ),
            });
        }

        Err(Error::InvalidInput {
            expected: "an OOBI URL or a key history (CESR)",
            cause: "unrecognized contact source".into(),
        })
    }

    /// Import a contact when you know their id and a witness that serves
    /// their key history. [`Keri::import_contact`] with an OOBI URL is the
    /// more common path.
    pub async fn import_contact_from(
        &self,
        id: &IdentityId,
        witness_url: &str,
    ) -> Result<IdentityId> {
        let location = crate::contact::discover(witness_url, &self.inner.retry).await?;

        let kel = crate::retry::with_retry(&self.inner.retry, || {
            let location = location.clone();
            async move {
                let ephemeral = crate::advanced::EphemeralIdentifier::new()?;
                Ok(ephemeral
                    .pull_kel(id.as_prefix(), 0, 100, &location)
                    .await?)
            }
        })
        .await?
        .ok_or_else(|| Error::ContactImportFailed {
            id: id.to_string(),
            cause: format!("the witness at {witness_url} does not know this identity"),
        })?;

        self.ingest_contact_kel(id.as_prefix(), kel.concat().as_bytes())
    }

    /// Store a contact's key history under `.contacts/<id>`.
    fn ingest_contact_kel(
        &self,
        aid: &keri_controller::IdentifierPrefix,
        kel: &[u8],
    ) -> Result<IdentityId> {
        let alias = format!(".contacts/{aid}");
        let controller = self.inner.store.controller_for(&alias)?;
        controller
            .process_kel_stream(kel)
            .map_err(|e| Error::ContactImportFailed {
                id: aid.to_string(),
                cause: format!("invalid key history: {e}"),
            })?;
        self.inner.store.save_id(&alias, aid)?;
        Ok(IdentityId::from(aid.clone()))
    }

    /// Check whether a credential is currently valid, revoked, or unknown.
    ///
    /// Checks registries already known locally first; if the credential is
    /// not found there, queries the network (with retries) through this
    /// store's identities. Returns [`CredentialStatus::Unknown`] when no
    /// registry anywhere knows the credential — for a foreign credential
    /// that usually means the issuer has not been imported yet
    /// ([`Keri::import_contact`]).
    pub async fn credential_status(&self, id: &CredentialId) -> Result<CredentialStatus> {
        let mut candidates = self.identities()?;
        candidates.extend(self.contact_aliases());

        // Local pass: no network.
        for alias in &candidates {
            let Ok(identifier) = self.inner.store.load(alias) else {
                continue;
            };
            if let Ok(status) =
                crate::advanced::tel::get_credential_status(&identifier, id.said())
            {
                let status: CredentialStatus = status.into();
                if status != CredentialStatus::Unknown {
                    return Ok(status);
                }
            }
        }

        // Network pass: refresh the registry state through any identity
        // that can sign queries.
        for alias in &self.identities()? {
            let Ok(identifier) = self.inner.store.load(alias) else {
                continue;
            };
            let Ok(signer) = self.inner.store.load_signer(alias) else {
                continue;
            };
            let refreshed = crate::retry::with_retry(&self.inner.retry, || {
                let signer = signer.clone();
                let identifier = &identifier;
                async move {
                    Ok(crate::advanced::tel::check_credential_status(
                        identifier,
                        &signer,
                        id.registry_prefix(),
                        id.said(),
                    )
                    .await?)
                }
            })
            .await;
            if let Ok(status) = refreshed {
                let status: CredentialStatus = status.into();
                if status != CredentialStatus::Unknown {
                    return Ok(status);
                }
            }
        }

        Ok(CredentialStatus::Unknown)
    }

    /// The retry policy used for network operations.
    pub fn retry_policy(&self) -> &RetryPolicy {
        &self.inner.retry
    }

    /// Low-level escape hatch: the alias-based store underneath this `Keri`.
    pub fn advanced(&self) -> &KeriStore {
        &self.inner.store
    }

    /// Aliases of imported contacts (none until `import_contact` is used).
    fn contact_aliases(&self) -> Vec<String> {
        let contacts_dir = self.inner.root.join(".contacts");
        let Ok(entries) = std::fs::read_dir(contacts_dir) else {
            return vec![];
        };
        entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().join("id").is_file())
            .filter_map(|e| e.file_name().to_str().map(|n| format!(".contacts/{n}")))
            .collect()
    }
}

/// Read the identifier (`"i"` field) of the first event in a KEL stream.
fn first_event_identifier(kel: &[u8]) -> Result<keri_controller::IdentifierPrefix> {
    let mut events = serde_json::Deserializer::from_slice(kel).into_iter::<serde_json::Value>();
    let first = events
        .next()
        .transpose()
        .ok()
        .flatten()
        .ok_or(Error::InvalidInput {
            expected: "key history (CESR) starting with a KERI event",
            cause: "no parseable event found".into(),
        })?;
    first
        .get("i")
        .and_then(|v| v.as_str())
        .ok_or(Error::InvalidInput {
            expected: "KERI event with an identifier field",
            cause: "first event has no `i` field".into(),
        })?
        .parse()
        .map_err(|e| Error::InvalidInput {
            expected: "identifier in key history",
            cause: format!("{e:?}"),
        })
}

fn expand_home(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(stripped);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_keri() -> (tempfile::TempDir, Keri) {
        let dir = tempfile::Builder::new().prefix("keri-facade").tempdir().unwrap();
        let keri = Keri::open(dir.path()).unwrap();
        (dir, keri)
    }

    #[tokio::test]
    async fn create_sign_verify_roundtrip_without_witnesses() {
        let (_dir, keri) = temp_keri();
        let alice = keri.new_identity("alice").build().await.unwrap();

        let signed = alice.sign(b"hello world").await.unwrap();
        assert_eq!(signed.signer(), alice.id());

        let verified = keri.verify(signed.as_cesr()).unwrap();
        assert_eq!(verified.payload, b"hello world");
        assert_eq!(&verified.signer, alice.id());
    }

    #[tokio::test]
    async fn identity_loads_across_reopen() {
        let dir = tempfile::Builder::new().prefix("keri-reopen").tempdir().unwrap();
        let id = {
            let keri = Keri::open(dir.path()).unwrap();
            let alice = keri.new_identity("alice").build().await.unwrap();
            alice.id().clone()
        };

        let keri = Keri::open(dir.path()).unwrap();
        let alice = keri.identity("alice").unwrap();
        assert_eq!(alice.id(), &id);

        let signed = alice.sign(b"still me").await.unwrap();
        let verified = keri.verify(signed.as_cesr()).unwrap();
        assert_eq!(verified.payload, b"still me");
    }

    #[tokio::test]
    async fn unknown_alias_is_a_clear_error() {
        let (_dir, keri) = temp_keri();
        let err = keri.identity("nobody").unwrap_err();
        assert!(matches!(err, Error::IdentityNotFound(a) if a == "nobody"));
    }

    #[tokio::test]
    async fn duplicate_alias_is_rejected() {
        let (_dir, keri) = temp_keri();
        keri.new_identity("alice").build().await.unwrap();
        let err = keri.new_identity("alice").build().await.unwrap_err();
        assert!(matches!(err, Error::IdentityExists(a) if a == "alice"));
    }

    #[tokio::test]
    async fn verify_rejects_unknown_signer() {
        let dir_a = tempfile::Builder::new().prefix("keri-a").tempdir().unwrap();
        let dir_b = tempfile::Builder::new().prefix("keri-b").tempdir().unwrap();
        let keri_a = Keri::open(dir_a.path()).unwrap();
        let keri_b = Keri::open(dir_b.path()).unwrap();

        let alice = keri_a.new_identity("alice").build().await.unwrap();
        let signed = alice.sign(b"who am I to you?").await.unwrap();

        // Bob's store has never heard of Alice.
        let err = keri_b.verify(signed.as_cesr()).unwrap_err();
        assert!(matches!(err, Error::UnknownSigner { id } if &id == alice.id()));
    }

    #[tokio::test]
    async fn identities_lists_created_aliases() {
        let (_dir, keri) = temp_keri();
        keri.new_identity("alice").build().await.unwrap();
        keri.new_identity("bob").build().await.unwrap();
        assert_eq!(keri.identities().unwrap(), vec!["alice", "bob"]);
    }

    #[tokio::test]
    async fn rotation_keeps_old_and_new_signatures_valid() {
        let (_dir, keri) = temp_keri();
        let alice = keri.new_identity("alice").build().await.unwrap();

        let before = alice.sign(b"before rotation").await.unwrap();
        alice.rotate().await.unwrap();
        let after = alice.sign(b"after rotation").await.unwrap();

        assert_eq!(
            keri.verify(before.as_cesr()).unwrap().payload,
            b"before rotation"
        );
        assert_eq!(
            keri.verify(after.as_cesr()).unwrap().payload,
            b"after rotation"
        );
    }
}
