//! String-friendly identifier newtypes used throughout the high-level API.
//!
//! Both types render to plain text with `Display`/`to_string()` and parse
//! back with `FromStr`/`parse()`, so applications can store and transmit them
//! as ordinary strings without touching CESR primitives.

use std::fmt;
use std::str::FromStr;

use keri_controller::IdentifierPrefix;
use said::SelfAddressingIdentifier;

use crate::error::{Error, Result};

/// The globally unique identifier of an identity (a KERI AID).
///
/// Renders as CESR text, e.g. `EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5`.
/// Two `IdentityId`s are equal exactly when they identify the same identity.
///
/// ```
/// use keri_sdk::IdentityId;
///
/// let id: IdentityId = "EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5".parse().unwrap();
/// assert_eq!(id.to_string(), "EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityId(pub(crate) IdentifierPrefix);

impl IdentityId {
    /// Access the underlying low-level prefix (escape hatch).
    pub fn as_prefix(&self) -> &IdentifierPrefix {
        &self.0
    }

    /// Consume and return the underlying low-level prefix (escape hatch).
    pub fn into_prefix(self) -> IdentifierPrefix {
        self.0
    }
}

impl From<IdentifierPrefix> for IdentityId {
    fn from(prefix: IdentifierPrefix) -> Self {
        IdentityId(prefix)
    }
}

impl fmt::Display for IdentityId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for IdentityId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let prefix = IdentifierPrefix::from_str(s).map_err(|e| Error::InvalidInput {
            expected: "identity id (CESR identifier prefix)",
            cause: e.to_string(),
        })?;
        Ok(IdentityId(prefix))
    }
}

impl serde::Serialize for IdentityId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for IdentityId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// The globally unique identifier of an issued credential.
///
/// Self-contained: it carries both the issuer's registry and the credential
/// digest, so [`crate::Keri::credential_status`] can check any credential —
/// including one issued by somebody else — from the id string alone.
///
/// Renders as `"<registry>:<credential digest>"`.
///
/// ```
/// use keri_sdk::CredentialId;
///
/// let s = "EBcLuJzcyYD8HUMNUAGcDjwdbsCMRLPbHuPWcyfRcUNA:ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";
/// let id: CredentialId = s.parse().unwrap();
/// assert_eq!(id.to_string(), s);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialId {
    pub(crate) registry: IdentifierPrefix,
    pub(crate) said: SelfAddressingIdentifier,
}

impl CredentialId {
    /// Build a credential id from its low-level parts (escape hatch).
    pub fn new(registry: IdentifierPrefix, said: SelfAddressingIdentifier) -> Self {
        CredentialId { registry, said }
    }

    /// The registry the credential was issued in, as CESR text.
    pub fn registry(&self) -> String {
        self.registry.to_string()
    }

    /// The credential's content digest (SAID), as CESR text.
    pub fn digest(&self) -> String {
        self.said.to_string()
    }

    /// Access the low-level registry prefix (escape hatch).
    pub fn registry_prefix(&self) -> &IdentifierPrefix {
        &self.registry
    }

    /// Access the low-level credential digest (escape hatch).
    pub fn said(&self) -> &SelfAddressingIdentifier {
        &self.said
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.registry, self.said)
    }
}

impl FromStr for CredentialId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (registry, said) = s.split_once(':').ok_or(Error::InvalidInput {
            expected: "credential id (\"<registry>:<digest>\")",
            cause: "missing ':' separator".to_string(),
        })?;
        let registry = IdentifierPrefix::from_str(registry).map_err(|e| Error::InvalidInput {
            expected: "credential id registry part",
            cause: e.to_string(),
        })?;
        let said =
            SelfAddressingIdentifier::from_str(said).map_err(|e| Error::InvalidInput {
                expected: "credential id digest part",
                cause: e.to_string(),
            })?;
        Ok(CredentialId { registry, said })
    }
}

impl serde::Serialize for CredentialId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for CredentialId {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AID: &str = "EJe6footPdcb6S7TKnEHEXgB-Ms_iH7krj0Ot4Vcjvr5";
    const SAID: &str = "ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux";

    #[test]
    fn identity_id_roundtrips_through_string() {
        let id: IdentityId = AID.parse().unwrap();
        assert_eq!(id.to_string(), AID);
        let again: IdentityId = id.to_string().parse().unwrap();
        assert_eq!(id, again);
    }

    #[test]
    fn identity_id_rejects_garbage() {
        let err = "not-an-identifier".parse::<IdentityId>().unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn credential_id_roundtrips_through_string() {
        let s = format!("{AID}:{SAID}");
        let id: CredentialId = s.parse().unwrap();
        assert_eq!(id.to_string(), s);
        assert_eq!(id.registry(), AID);
        assert_eq!(id.digest(), SAID);
    }

    #[test]
    fn credential_id_rejects_missing_separator() {
        let err = SAID.parse::<CredentialId>().unwrap_err();
        assert!(matches!(err, Error::InvalidInput { .. }));
    }

    #[test]
    fn ids_serialize_as_plain_strings() {
        let id: IdentityId = AID.parse().unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{AID}\""));

        let cred: CredentialId = format!("{AID}:{SAID}").parse().unwrap();
        let json = serde_json::to_string(&cred).unwrap();
        let back: CredentialId = serde_json::from_str(&json).unwrap();
        assert_eq!(cred, back);
    }
}
