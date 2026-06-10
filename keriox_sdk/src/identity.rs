//! The [`Identity`] handle — your own identity in a [`crate::Keri`] store —
//! and the [`IdentityBuilder`] that creates one.

use std::sync::Arc;

use crate::advanced::types::IdentifierConfig;
use crate::advanced::SignerAlgorithm;
use crate::contact::discover;
use crate::error::{Error, Result};
use crate::ids::{CredentialId, IdentityId};
use crate::keri::KeriInner;
use crate::message::SignedMessage;

/// The signature algorithm an identity's keys use.
///
/// `Ed25519` is the default and right for most applications. Pick `P256`
/// when keys must live in platform hardware (iOS Secure Enclave, Android
/// Keystore), `Secp256k1` for Bitcoin/Ethereum-adjacent ecosystems.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyAlgorithm {
    /// Ed25519 — fast, compact, the KERI default.
    #[default]
    Ed25519,
    /// NIST P-256 — supported by mobile secure hardware.
    P256,
    /// secp256k1 — the curve used by Bitcoin and Ethereum.
    Secp256k1,
}

impl From<KeyAlgorithm> for SignerAlgorithm {
    fn from(a: KeyAlgorithm) -> Self {
        match a {
            KeyAlgorithm::Ed25519 => SignerAlgorithm::Ed25519,
            KeyAlgorithm::P256 => SignerAlgorithm::EcdsaSecp256r1,
            KeyAlgorithm::Secp256k1 => SignerAlgorithm::EcdsaSecp256k1,
        }
    }
}

/// How an identity's signing keys are managed.
#[derive(Clone)]
pub(crate) enum Keys {
    /// Seeds stored (encrypted by the OS user account only) in the store
    /// directory; loaded on demand.
    Software,
    /// Keys held by an external provider (mobile keystore, HSM). The current
    /// signer and the provider holding the committed next key.
    #[cfg(feature = "keyprovider")]
    Provider {
        current: crate::advanced::keyprovider_adapter::KeriSigner,
        next: Arc<dyn keri_keyprovider::KeyProvider>,
    },
}

/// One identity you control, stored under an alias in a [`crate::Keri`] store.
///
/// Cheap to clone; safe to share across tasks. Obtain it from
/// [`crate::Keri::new_identity`] (create) or [`crate::Keri::identity`] (load).
#[derive(Clone)]
pub struct Identity {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) alias: String,
    pub(crate) id: IdentityId,
    pub(crate) keys: Keys,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("alias", &self.alias)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// This identity's globally unique id — share it freely; it is public.
    pub fn id(&self) -> &IdentityId {
        &self.id
    }

    /// The local alias this identity is stored under.
    pub fn alias(&self) -> &str {
        &self.alias
    }

    /// Sign a payload. The result is a self-contained CESR string anyone can
    /// verify with [`crate::Keri::verify`] once they know this identity.
    pub async fn sign(&self, payload: &[u8]) -> Result<SignedMessage> {
        let identifier = self.keri.store.load(&self.alias)?;
        let envelope = match &self.keys {
            Keys::Software => {
                let signer = self.keri.store.load_signer(&self.alias)?;
                crate::advanced::signing::sign(&identifier, &signer, payload)?
            }
            #[cfg(feature = "keyprovider")]
            Keys::Provider { current, .. } => {
                crate::advanced::signing::sign(&identifier, current, payload)?
            }
        };
        Ok(SignedMessage {
            cesr: envelope.cesr,
            signer: self.id.clone(),
        })
    }

    /// Rotate to fresh keys.
    ///
    /// The next key was committed in advance (KERI pre-rotation), so a stolen
    /// current key cannot hijack the identity. A new next key is generated
    /// and committed automatically; witnesses are notified and receipts
    /// collected before this returns. Messages signed before the rotation
    /// remain verifiable.
    pub async fn rotate(&self) -> Result<()> {
        match &self.keys {
            Keys::Software => {
                let alias = self.alias.clone();
                let keri = self.keri.clone();
                crate::retry::with_retry(&self.keri.retry, || {
                    let keri = keri.clone();
                    let alias = alias.clone();
                    async move { Ok(keri.store.rotate(&alias).await?) }
                })
                .await
            }
            #[cfg(feature = "keyprovider")]
            Keys::Provider { .. } => Err(Error::InvalidInput {
                expected: "software-keyed identity for rotate()",
                cause: "this identity's keys live in an external key provider; \
                        rotate with Identity::rotate_with_provider(new_next_provider)"
                    .into(),
            }),
        }
    }

    /// Rotate a provider-backed identity (mobile keystore, HSM).
    ///
    /// The provider holding the previously committed next key signs the
    /// rotation, and `new_next` becomes the next committed key. After this
    /// call the identity signs with the former `next` provider; keep handles
    /// to your providers — the SDK cannot create keys inside your keystore.
    #[cfg(feature = "keyprovider")]
    pub async fn rotate_with_provider(
        &mut self,
        new_next: Arc<dyn keri_keyprovider::KeyProvider>,
    ) -> Result<()> {
        use crate::advanced::keyprovider_adapter::{basic_prefix_for, KeriSigner};

        let Keys::Provider { next, .. } = &self.keys else {
            return Err(Error::InvalidInput {
                expected: "provider-backed identity",
                cause: "this identity uses software keys; call rotate() instead".into(),
            });
        };

        let revealing_signer = KeriSigner::Provider(next.clone());
        let new_next_pk = basic_prefix_for(
            new_next.algorithm(),
            keri_core::keys::PublicKey::new(new_next.public_key().bytes.clone()),
            false,
        );

        let mut identifier = self.keri.store.load(&self.alias)?;
        let config = crate::advanced::types::RotationConfig {
            new_next_pk,
            new_next_threshold: 1,
            witness_to_add: vec![],
            witness_to_remove: vec![],
            witness_threshold: 0,
        };
        crate::advanced::operations::rotate(&mut identifier, revealing_signer.clone(), config)
            .await?;

        self.keys = Keys::Provider {
            current: revealing_signer,
            next: new_next,
        };
        Ok(())
    }

    /// Issue a credential: anchor the payload's digest in this identity's
    /// public registry so anyone can later check it has not been revoked.
    ///
    /// The registry is created automatically on first issuance. JSON
    /// payloads with a `d` field get the digest embedded (the standard
    /// self-addressing layout); any other payload is digested as-is.
    pub async fn issue(&self, payload: &[u8]) -> Result<crate::credential::Credential> {
        match &self.keys {
            Keys::Software => {
                let signer = self.keri.store.load_signer(&self.alias)?;
                self.issue_with(signer, payload).await
            }
            #[cfg(feature = "keyprovider")]
            Keys::Provider { current, .. } => self.issue_with(current.clone(), payload).await,
        }
    }

    /// Revoke a credential previously issued by this identity. The change
    /// is published through the witnesses; status checks anywhere will see
    /// `Revoked` once they refresh.
    pub async fn revoke(&self, credential: &CredentialId) -> Result<()> {
        match &self.keys {
            Keys::Software => {
                let signer = self.keri.store.load_signer(&self.alias)?;
                self.revoke_with(signer, credential).await
            }
            #[cfg(feature = "keyprovider")]
            Keys::Provider { current, .. } => self.revoke_with(current.clone(), credential).await,
        }
    }

    /// The credentials this identity has issued (most recent last).
    pub fn credentials(&self) -> Result<Vec<CredentialId>> {
        let path = self.keri.root.join(&self.alias).join("credentials");
        if !path.exists() {
            return Ok(vec![]);
        }
        let content = std::fs::read_to_string(&path).map_err(|e| Error::Storage {
            path: path.clone(),
            cause: e.to_string(),
        })?;
        content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.trim().parse())
            .collect()
    }

    async fn issue_with<S>(&self, signer: S, payload: &[u8]) -> Result<crate::credential::Credential>
    where
        S: crate::advanced::operations::SigningBackend + Clone + 'static,
    {
        // First issuance creates the registry and persists its id, so the
        // application never has to manage registry state itself.
        let registry = match self.keri.store.load(&self.alias)?.registry_id() {
            Some(r) => r.clone(),
            None => {
                let registry = crate::retry::with_retry(&self.keri.retry, || {
                    let signer = signer.clone();
                    async move {
                        let mut identifier = self.keri.store.load(&self.alias)?;
                        Ok(crate::advanced::operations::incept_registry(
                            &mut identifier,
                            signer,
                        )
                        .await?)
                    }
                })
                .await?;
                self.keri.store.save_registry(&self.alias, &registry)?;
                registry
            }
        };

        let (payload, said) = prepare_credential_payload(payload)?;

        crate::retry::with_retry(&self.keri.retry, || {
            let signer = signer.clone();
            let said = said.clone();
            async move {
                // Reload so the handle knows its registry and latest state.
                let mut identifier = self.keri.store.load(&self.alias)?;
                Ok(crate::advanced::operations::issue(&mut identifier, signer, said).await?)
            }
        })
        .await?;

        let id = CredentialId::new(registry, said);
        self.append_credential_index(&id)?;
        Ok(crate::credential::Credential {
            id,
            payload,
            issuer: self.id.clone(),
        })
    }

    async fn revoke_with<S>(&self, signer: S, credential: &CredentialId) -> Result<()>
    where
        S: crate::advanced::operations::SigningBackend + Clone + 'static,
    {
        crate::retry::with_retry(&self.keri.retry, || {
            let signer = signer.clone();
            async move {
                let mut identifier = self.keri.store.load(&self.alias)?;
                Ok(
                    crate::advanced::operations::revoke(&mut identifier, signer, credential.said())
                        .await?,
                )
            }
        })
        .await
    }

    fn append_credential_index(&self, id: &CredentialId) -> Result<()> {
        use std::io::Write;
        let path = self.keri.root.join(&self.alias).join("credentials");
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| Error::Storage {
                path: path.clone(),
                cause: e.to_string(),
            })?;
        writeln!(file, "{id}").map_err(|e| Error::Storage {
            path,
            cause: e.to_string(),
        })
    }

    /// This identity's full key history (KEL) as a CESR stream — for
    /// out-of-band sharing with parties that cannot reach your witnesses.
    pub fn kel(&self) -> Result<String> {
        let identifier = self.keri.store.load(&self.alias)?;
        let kel = identifier
            .get_own_kel_cesr()
            .ok_or_else(|| Error::IdentityNotFound(self.alias.clone()))??;
        Ok(kel)
    }

    /// The witness URLs currently serving this identity.
    pub fn witnesses(&self) -> Result<Vec<String>> {
        let identifier = self.keri.store.load(&self.alias)?;
        let witness_ids: Vec<_> = identifier.witnesses().collect();
        let mut urls = vec![];
        for w in witness_ids {
            for loc in identifier
                .get_location(&keri_controller::IdentifierPrefix::Basic(w))
                .unwrap_or_default()
            {
                urls.push(loc.url.to_string());
            }
        }
        Ok(urls)
    }

    /// Low-level escape hatch: the mid-level identifier handle and (for
    /// software keys) its current signer.
    pub fn advanced(
        &self,
    ) -> Result<(
        crate::advanced::Identifier,
        Option<Arc<keri_core::signer::Signer>>,
    )> {
        let identifier = self.keri.store.load(&self.alias)?;
        let signer = match &self.keys {
            Keys::Software => Some(self.keri.store.load_signer(&self.alias)?),
            #[cfg(feature = "keyprovider")]
            Keys::Provider { .. } => None,
        };
        Ok((identifier, signer))
    }
}

/// Prepare a credential payload for issuance: JSON documents with a `d`
/// field get the digest embedded (self-addressing data); anything else is
/// digested as-is.
fn prepare_credential_payload(
    payload: &[u8],
) -> Result<(Vec<u8>, keri_core::actor::prelude::SelfAddressingIdentifier)> {
    use said::derivation::HashFunctionCode;

    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(payload) {
        if value.is_object() && value.get("d").is_some() {
            let json = std::str::from_utf8(payload).map_err(|e| Error::InvalidInput {
                expected: "UTF-8 JSON credential payload",
                cause: e.to_string(),
            })?;
            let saidified =
                crate::advanced::signing::saidify_json(json, HashFunctionCode::Blake3_256)?;
            let value: serde_json::Value =
                serde_json::from_str(&saidified).map_err(|e| Error::InvalidInput {
                    expected: "JSON credential payload",
                    cause: e.to_string(),
                })?;
            let said = value["d"]
                .as_str()
                .unwrap_or_default()
                .parse()
                .map_err(|e| Error::InvalidInput {
                    expected: "self-addressing digest in `d` field",
                    cause: format!("{e:?}"),
                })?;
            return Ok((saidified.into_bytes(), said));
        }
    }
    Ok((payload.to_vec(), crate::advanced::signing::content_sai(payload)))
}

/// Builder for a new identity. Created by [`crate::Keri::new_identity`];
/// finished with [`IdentityBuilder::build`].
pub struct IdentityBuilder {
    pub(crate) keri: Arc<KeriInner>,
    pub(crate) alias: String,
    pub(crate) witness_urls: Vec<String>,
    pub(crate) watcher_urls: Vec<String>,
    pub(crate) witness_threshold: Option<u64>,
    pub(crate) algorithm: KeyAlgorithm,
    #[cfg(feature = "keyprovider")]
    pub(crate) providers: Option<(
        Arc<dyn keri_keyprovider::KeyProvider>,
        Arc<dyn keri_keyprovider::KeyProvider>,
    )>,
}

impl IdentityBuilder {
    pub(crate) fn new(keri: Arc<KeriInner>, alias: &str) -> Self {
        IdentityBuilder {
            keri,
            alias: alias.to_string(),
            witness_urls: vec![],
            watcher_urls: vec![],
            witness_threshold: None,
            algorithm: KeyAlgorithm::default(),
            #[cfg(feature = "keyprovider")]
            providers: None,
        }
    }

    /// Add a witness by its base URL (e.g. `"http://witness.example:3232"`).
    ///
    /// Witnesses countersign and publish your key history so others can
    /// verify your signatures while you are offline. At least one is needed
    /// for anything beyond local experiments.
    pub fn witness(mut self, url: impl Into<String>) -> Self {
        self.witness_urls.push(url.into());
        self
    }

    /// How many witness receipts are required (default: all witnesses).
    pub fn witness_threshold(mut self, threshold: u64) -> Self {
        self.witness_threshold = Some(threshold);
        self
    }

    /// Add a watcher by its base URL. Watchers fetch *other people's* key
    /// histories on your behalf — needed to verify identities you import.
    pub fn watcher(mut self, url: impl Into<String>) -> Self {
        self.watcher_urls.push(url.into());
        self
    }

    /// Choose the key algorithm (default: Ed25519).
    pub fn key_algorithm(mut self, algorithm: KeyAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Use external key providers (mobile keystore, HSM) instead of
    /// software keys: `current` signs from day one, `next` is committed as
    /// the rotation key. No key material is written to disk.
    #[cfg(feature = "keyprovider")]
    pub fn key_providers(
        mut self,
        current: Arc<dyn keri_keyprovider::KeyProvider>,
        next: Arc<dyn keri_keyprovider::KeyProvider>,
    ) -> Self {
        self.providers = Some((current, next));
        self
    }

    /// Create the identity: discover the witnesses, publish the inception
    /// event, collect witness receipts, and persist everything under the
    /// alias.
    pub async fn build(self) -> Result<Identity> {
        if self.keri.alias_exists(&self.alias) {
            return Err(Error::IdentityExists(self.alias));
        }

        let mut witnesses = vec![];
        for url in &self.witness_urls {
            witnesses.push(discover(url, &self.keri.retry).await?);
        }
        let mut watchers = vec![];
        for url in &self.watcher_urls {
            watchers.push(discover(url, &self.keri.retry).await?);
        }

        let witness_threshold = match self.witness_threshold {
            Some(t) => t,
            None => witnesses.len() as u64,
        };

        let config = IdentifierConfig {
            witnesses,
            witness_threshold,
            watchers,
            algorithm: self.algorithm.into(),
        };

        #[cfg(feature = "keyprovider")]
        if let Some((current, next)) = self.providers {
            use crate::advanced::keyprovider_adapter::basic_prefix_for;
            let next_pk = basic_prefix_for(
                next.algorithm(),
                keri_core::keys::PublicKey::new(next.public_key().bytes.clone()),
                false,
            );
            let (identifier, signer) = self
                .keri
                .store
                .create_with_provider(&self.alias, current, next_pk, config)
                .await?;
            return Ok(Identity {
                id: IdentityId::from(identifier.id().clone()),
                keri: self.keri,
                alias: self.alias,
                keys: Keys::Provider {
                    current: signer,
                    next,
                },
            });
        }

        let (identifier, _signer) = self.keri.store.create(&self.alias, config).await?;
        Ok(Identity {
            id: IdentityId::from(identifier.id().clone()),
            keri: self.keri,
            alias: self.alias,
            keys: Keys::Software,
        })
    }
}
