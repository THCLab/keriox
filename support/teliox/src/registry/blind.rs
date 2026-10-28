//! Blinded state blocks of blindable updates (`bup`): the transaction ACDC
//! SAID and its state, hidden behind a digest, the BLID, that the `bup`
//! carries in `b` (ACDC specification, "Blinded Attribute Block"). A block is
//! a fixed concatenation of CESR primitives, `[d, u, td, ts]`, or, bound to
//! the Issuee's key state at the time, `[d, u, td, ts, bn, bd]`. It travels
//! as an attachment in a `-a` or `-b` group.

use argon2::{Algorithm, Argon2, Params, Version};
use cesrox::{
    group::{BlindedState as BlindedGroup, BoundState as BoundGroup, Group},
    parse_value,
    primitives::{
        codes::{material::MaterialCode, number::pack_number, tag::TagCode, PrimitiveCode},
        Primitive,
    },
    value::Value,
};
use said::{
    derivation::{HashFunction, HashFunctionCode},
    SelfAddressingIdentifier,
};

use super::RegistryError;

/// `1AAP`: the CESR empty value, for a placeholder field.
const EMPTY: &str = "1AAP";

/// A blinded state block.
#[derive(Debug, Clone, PartialEq)]
pub struct BlindedState {
    /// The BLID: the digest of the block.
    pub blid: SelfAddressingIdentifier,
    /// The blinding factor; `None` for an unblinded, public update.
    pub uuid: Option<String>,
    /// The transaction ACDC SAID; `None` for a placeholder.
    pub acdc: Option<SelfAddressingIdentifier>,
    /// The transaction state; empty for a placeholder.
    pub state: String,
    /// The Issuee key event the state is bound to: its sequence number and
    /// SAID, or a placeholder (0 and `None`).
    pub bound: Option<(u64, Option<SelfAddressingIdentifier>)>,
}

impl BlindedState {
    /// The block with its BLID computed.
    pub fn new(
        uuid: Option<String>,
        acdc: Option<SelfAddressingIdentifier>,
        state: &str,
        bound: Option<(u64, Option<SelfAddressingIdentifier>)>,
    ) -> Result<Self, RegistryError> {
        let mut block = BlindedState {
            blid: SelfAddressingIdentifier::default(),
            uuid,
            acdc,
            state: state.to_string(),
            bound,
        };
        block.blid = block.compute_blid()?;
        Ok(block)
    }

    /// The block blinded for update `sn` of a registry, with the blind
    /// derived from the salt the Issuer shares with the Discloser.
    pub fn blind(
        salt: &Salt,
        sn: u64,
        acdc: Option<SelfAddressingIdentifier>,
        state: &str,
        bound: Option<(u64, Option<SelfAddressingIdentifier>)>,
    ) -> Result<Self, RegistryError> {
        Self::new(Some(salt.blind(sn)?), acdc, state, bound)
    }

    /// The block behind `blid` among those `salt` blinds for update `sn`,
    /// trying the ACDC and its placeholder with each of `states`: what the
    /// Discloser does to learn the state of an update.
    pub fn unblind(
        blid: &SelfAddressingIdentifier,
        salt: &Salt,
        sn: u64,
        acdc: &SelfAddressingIdentifier,
        states: &[&str],
    ) -> Result<Option<Self>, RegistryError> {
        let uuid = salt.blind(sn)?;
        for target in [Some(acdc.clone()), None] {
            for state in states.iter().copied().chain([""]) {
                let block = Self::new(Some(uuid.clone()), target.clone(), state, None)?;
                if &block.blid == blid {
                    return Ok(Some(block));
                }
            }
        }
        Ok(None)
    }

    /// Whether the block's fields reproduce its BLID.
    pub fn verify(&self) -> bool {
        self.compute_blid().is_ok_and(|blid| blid == self.blid)
    }

    /// The qb64 of the fields after `d`.
    fn tail(&self) -> Result<String, RegistryError> {
        let mut tail = self.uuid.clone().unwrap_or_else(|| EMPTY.into());
        tail += &self
            .acdc
            .as_ref()
            .map_or(EMPTY.to_string(), |said| said.to_string());
        tail += &label(&self.state)?;
        if let Some((sn, said)) = &self.bound {
            tail += &pack_number(*sn as u128);
            tail += &said.as_ref().map_or(EMPTY.to_string(), |said| said.to_string());
        }
        Ok(tail)
    }

    /// The BLID: a SAID over the concatenated qb64 fields, `d` dummied.
    fn compute_blid(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        let function = HashFunction::from(HashFunctionCode::Blake3_256);
        let dummied = "#".repeat(function.get_len()) + &self.tail()?;
        Ok(function.derive(dummied.as_bytes()))
    }

    /// The block as the qb64 concatenation of its fields.
    pub fn to_qb64(&self) -> Result<String, RegistryError> {
        Ok(self.blid.to_string() + &self.tail()?)
    }

    /// The block as an attachment group, `-a` or, when bound, `-b`.
    pub fn to_group(&self) -> Result<Group, RegistryError> {
        let value = |qb64: &str| -> Result<Value, RegistryError> {
            match parse_value(qb64.as_bytes()) {
                Ok((value, [])) => Ok(value),
                _ => Err(RegistryError::Format(format!("{qb64} is not one CESR value"))),
            }
        };
        let digest = value(&self.blid.to_string())?;
        let uuid = value(self.uuid.as_deref().unwrap_or(EMPTY))?;
        let said = value(&self.acdc.as_ref().map_or(EMPTY.to_string(), |s| s.to_string()))?;
        let state = value(&label(&self.state)?)?;
        Ok(match &self.bound {
            None => Group::BlindedStates(vec![BlindedGroup {
                digest,
                uuid,
                said,
                state,
            }]),
            Some((sn, bound)) => Group::BoundStates(vec![BoundGroup {
                digest,
                uuid,
                said,
                state,
                bound_sn: *sn as u128,
                bound_said: value(&bound.as_ref().map_or(EMPTY.to_string(), |s| s.to_string()))?,
            }]),
        })
    }

    /// The blocks of a `-a` or `-b` group.
    pub fn from_group(group: &Group) -> Result<Vec<Self>, RegistryError> {
        let blocks = match group {
            Group::BlindedStates(states) => states
                .iter()
                .map(|s| read(&s.digest, &s.uuid, &s.said, &s.state, None))
                .collect(),
            Group::BoundStates(states) => states
                .iter()
                .map(|s| {
                    let sn = u64::try_from(s.bound_sn)
                        .map_err(|_| RegistryError::Format("bound sequence number".into()))?;
                    let said = optional_said(&s.bound_said)?;
                    read(&s.digest, &s.uuid, &s.said, &s.state, Some((sn, said)))
                })
                .collect(),
            _ => Err(RegistryError::Format("not a blinded state group".into())),
        }?;
        Ok(blocks)
    }
}

fn read(
    digest: &Value,
    uuid: &Value,
    said: &Value,
    state: &Value,
    bound: Option<(u64, Option<SelfAddressingIdentifier>)>,
) -> Result<BlindedState, RegistryError> {
    let text = |value: &Value| value.to_string();
    let blid = text(digest)
        .parse()
        .map_err(|_| RegistryError::Format("BLID is not a digest".into()))?;
    let uuid = match text(uuid) {
        empty if empty == EMPTY => None,
        nonce if nonce.starts_with('a') && nonce.len() == 44 => Some(nonce),
        other => return Err(RegistryError::Format(format!("{other} is not a blind"))),
    };
    let state = match state {
        Value::Tag(tag) => tag.tag().to_string(),
        other if text(other) == EMPTY => String::new(),
        other => {
            return Err(RegistryError::Format(format!(
                "{} is not a state label",
                text(other)
            )))
        }
    };
    let block = BlindedState {
        blid,
        uuid,
        acdc: optional_said(said)?,
        state,
        bound,
    };
    Ok(block)
}

fn optional_said(value: &Value) -> Result<Option<SelfAddressingIdentifier>, RegistryError> {
    match value.to_string() {
        empty if empty == EMPTY => Ok(None),
        said => said
            .parse()
            .map(Some)
            .map_err(|_| RegistryError::Format(format!("{said} is not a SAID"))),
    }
}

/// A state label as CESR: empty, or a tag of up to 11 Base64 characters.
fn label(state: &str) -> Result<String, RegistryError> {
    use cesrox::derivation_code::DerivationCode;
    if state.is_empty() {
        return Ok(EMPTY.into());
    }
    TagCode::new(state)
        .map(|tag| tag.to_str())
        .map_err(|_| RegistryError::Format(format!("state {state:?} is not a label")))
}

/// The secret salt from which the blinds of a registry's updates are
/// derived, shared by the Issuer and the Discloser.
#[derive(Clone, PartialEq)]
pub struct Salt([u8; 16]);

impl std::fmt::Debug for Salt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Salt(..)")
    }
}

impl Salt {
    pub fn new(raw: [u8; 16]) -> Self {
        Salt(raw)
    }

    /// A fresh random salt.
    pub fn random() -> Self {
        let mut raw = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
        Salt(raw)
    }

    /// The salt as a qb64 128-bit salt (`0A`).
    pub fn to_qb64(&self) -> String {
        Value::Primitive(Primitive::new(
            PrimitiveCode::Random(cesrox::primitives::codes::rand_128::Rand128Code),
            self.0.to_vec(),
        ))
        .to_string()
    }

    pub fn from_qb64(qb64: &str) -> Result<Self, RegistryError> {
        match parse_value(qb64.as_bytes()) {
            Ok((Value::Primitive(primitive), []))
                if matches!(primitive.code, PrimitiveCode::Random(_)) =>
            {
                Ok(Salt(primitive.raw.try_into().map_err(|_| {
                    RegistryError::Format("salt is not 16 bytes".into())
                })?))
            }
            _ => Err(RegistryError::Format(format!("{qb64} is not a 128-bit salt"))),
        }
    }

    /// The blind of update `sn`: a 256-bit salty nonce stretched with
    /// Argon2id from the salt, with the hex sequence number as the path, at
    /// keripy's `low` tier for blinding factors (2 passes, 64 MiB).
    pub fn blind(&self, sn: u64) -> Result<String, RegistryError> {
        let params = Params::new(65_536, 2, 1, Some(32))
            .map_err(|e| RegistryError::Format(e.to_string()))?;
        let mut raw = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(format!("{sn:x}").as_bytes(), &self.0, &mut raw)
            .map_err(|e| RegistryError::Format(e.to_string()))?;
        Ok(Value::Primitive(Primitive::new(
            PrimitiveCode::Material(MaterialCode::Salt256),
            raw.to_vec(),
        ))
        .to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::{BlindedState, Salt};
    use crate::registry::tests::keripy;

    fn said(text: &str) -> said::SelfAddressingIdentifier {
        text.parse().unwrap()
    }

    /// The blinds keriox derives from keripy's salt, and the blocks and
    /// BLIDs it computes, are keripy's.
    #[test]
    fn blinded_blocks_are_keripys() {
        let vectors = keripy();
        let salt = Salt::from_qb64(vectors["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salt.to_qb64(), vectors["salt"].as_str().unwrap());
        let acdc = said(vectors["acdc"].as_str().unwrap());
        for update in vectors["updates"].as_array().unwrap() {
            let sn = update["sn"].as_u64().unwrap();
            let state = update["state"].as_str().unwrap();
            assert_eq!(salt.blind(sn).unwrap(), update["uuid"].as_str().unwrap());
            let block = BlindedState::blind(&salt, sn, Some(acdc.clone()), state, None).unwrap();
            assert_eq!(block.blid.to_string(), update["blid"].as_str().unwrap());
            assert_eq!(block.to_qb64().unwrap(), update["block"].as_str().unwrap());
            assert!(block.verify());
        }

        let public = BlindedState::new(None, Some(acdc.clone()), "issued", None).unwrap();
        assert_eq!(
            public.to_qb64().unwrap(),
            vectors["public_block"]["block"].as_str().unwrap()
        );

        let bound = BlindedState::blind(
            &salt,
            1,
            Some(acdc),
            "issued",
            Some((3, Some(said("ELC5L3iBVD77d_MYbYGGCUQgqQBju1o4x1Ud-z2sL-ux")))),
        )
        .unwrap();
        assert_eq!(
            bound.to_qb64().unwrap(),
            vectors["bound_block"]["block"].as_str().unwrap()
        );
    }

    /// A block survives its attachment group, and the Discloser finds the
    /// state behind a BLID from the salt alone.
    #[test]
    fn a_block_is_carried_in_its_group_and_unblinded() {
        let vectors = keripy();
        let salt = Salt::from_qb64(vectors["salt"].as_str().unwrap()).unwrap();
        let acdc = said(vectors["acdc"].as_str().unwrap());
        let revoked = &vectors["updates"][1];
        let block = BlindedState::blind(&salt, 2, Some(acdc.clone()), "revoked", None).unwrap();
        let bound = BlindedState::blind(&salt, 2, Some(acdc.clone()), "issued", Some((0, None)))
            .unwrap();
        for block in [&block, &bound] {
            let group = block.to_group().unwrap();
            assert_eq!(BlindedState::from_group(&group).unwrap(), vec![block.clone()]);
        }

        let blid = said(revoked["blid"].as_str().unwrap());
        let found = BlindedState::unblind(&blid, &salt, 2, &acdc, &["issued", "revoked"])
            .unwrap()
            .unwrap();
        assert_eq!(found.state, "revoked");
        assert!(BlindedState::unblind(&blid, &salt, 1, &acdc, &["issued", "revoked"])
            .unwrap()
            .is_none());
    }

    /// A block whose fields do not reproduce its BLID proves nothing.
    #[test]
    fn a_changed_block_does_not_verify() {
        let salt = Salt::random();
        let mut block = BlindedState::blind(&salt, 1, None, "issued", None).unwrap();
        assert!(block.verify());
        block.state = "revoked".into();
        assert!(!block.verify());
        assert!(BlindedState::new(None, None, "not a label!", None).is_err());
    }
}
