//! Blinded state blocks of blindable updates (`bup`): the transaction ACDC
//! SAID and its state, hidden behind a digest, the BLID, that the `bup`
//! carries in `b` (ACDC specification, "Blinded Attribute Block"). acdc-rust
//! reads and writes them; this adds the blinding salt an Issuer shares with
//! its Disclosers, and one type for blocks bound to the Issuee's key state
//! and blocks that are not.

use acdc::registry::{derive_uuid, BlindedState, BoundState};
use cesrox::{
    parse_value,
    primitives::{codes::PrimitiveCode, Primitive},
    value::Value,
};
use said::{derivation::HashFunctionCode, SelfAddressingIdentifier};

use super::RegistryError;

fn format(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Format(e.to_string())
}

fn said(text: &str) -> Result<SelfAddressingIdentifier, RegistryError> {
    text.parse()
        .map_err(|_| RegistryError::Format(format!("{text} is not a SAID")))
}

/// A state block, as it travels in a `-a` (blinded) or `-b` (bound) group.
#[derive(Debug, Clone, PartialEq)]
pub enum StateBlock {
    Blinded(BlindedState),
    /// Bound to the Issuee's key event at the time of the update.
    Bound(BoundState),
}

impl StateBlock {
    /// The block of update `sn` giving `acdc` the `state`, blinded with the
    /// blind `blinding` derives for `sn`. An empty `state` and no `acdc`
    /// make a placeholder.
    pub fn new(
        blinding: &Blinding,
        sn: u64,
        acdc: Option<&SelfAddressingIdentifier>,
        state: &str,
    ) -> Result<Self, RegistryError> {
        let uuid = blinding.blind(sn)?;
        let acdc = acdc.map(ToString::to_string).unwrap_or_default();
        BlindedState::new(&uuid, &acdc, state, HashFunctionCode::Blake3_256)
            .map(StateBlock::Blinded)
            .map_err(format)
    }

    /// The block of update `sn` with the state found behind `blid`, trying
    /// `acdc` and the placeholder with each of `states`: what the Discloser
    /// does to learn the state of an update.
    pub fn unblind(
        blid: &SelfAddressingIdentifier,
        blinding: &Blinding,
        sn: u64,
        acdc: &SelfAddressingIdentifier,
        states: &[&str],
    ) -> Result<Option<Self>, RegistryError> {
        let uuid = blinding.blind(sn)?;
        Ok(
            BlindedState::unblind(&blid.to_string(), &uuid, &acdc.to_string(), states)
                .map(StateBlock::Blinded),
        )
    }

    pub fn blid(&self) -> Result<SelfAddressingIdentifier, RegistryError> {
        said(match self {
            StateBlock::Blinded(block) => block.blid(),
            StateBlock::Bound(block) => block.blid(),
        })
    }

    /// The transaction ACDC; none for a placeholder.
    pub fn acdc(&self) -> Result<Option<SelfAddressingIdentifier>, RegistryError> {
        let acdc = match self {
            StateBlock::Blinded(block) => block.acdc(),
            StateBlock::Bound(block) => block.acdc(),
        };
        (!acdc.is_empty()).then(|| said(acdc)).transpose()
    }

    /// The transaction state; empty for a placeholder.
    pub fn state(&self) -> &str {
        match self {
            StateBlock::Blinded(block) => block.state(),
            StateBlock::Bound(block) => block.state(),
        }
    }

    /// The block as its attachment group.
    pub fn to_group(&self) -> Result<String, RegistryError> {
        match self {
            StateBlock::Blinded(block) => BlindedState::enclose(std::slice::from_ref(block)),
            StateBlock::Bound(block) => BoundState::enclose(std::slice::from_ref(block)),
        }
        .map_err(format)
    }

    /// The blocks of a `-a` or `-b` group; each BLID is verified.
    pub fn parse_group(text: &str) -> Result<Vec<Self>, RegistryError> {
        if text.starts_with("-b") {
            BoundState::parse_group(text)
                .map(|blocks| blocks.into_iter().map(StateBlock::Bound).collect())
        } else {
            BlindedState::parse_group(text)
                .map(|blocks| blocks.into_iter().map(StateBlock::Blinded).collect())
        }
        .map_err(format)
    }
}

/// How a registry's blocks are blinded. The Issuer keeps it, with its other
/// secrets, for as long as it updates the registry, and shares it only with
/// Disclosers.
#[derive(Clone, PartialEq)]
pub enum Blinding {
    /// Each block is blinded with a blind derived from the salt for its
    /// update.
    Private(Salt),
    /// Blocks carry no blind: anyone can tell the state behind a BLID from
    /// the ACDC SAID and the possible states.
    Public,
}

impl std::fmt::Debug for Blinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Blinding::Private(_) => f.write_str("Private(..)"),
            Blinding::Public => f.write_str("Public"),
        }
    }
}

impl Blinding {
    /// Private blinding with a fresh salt.
    pub fn private() -> Self {
        Blinding::Private(Salt::random())
    }

    /// The blind of update `sn`; empty for public blinding.
    fn blind(&self, sn: u64) -> Result<String, RegistryError> {
        match self {
            Blinding::Private(salt) => salt.blind(sn),
            Blinding::Public => Ok(String::new()),
        }
    }
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
        Self::from_qb64(&acdc::nonce::salt()).expect("acdc makes 128-bit salts")
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
            _ => Err(RegistryError::Format(format!(
                "{qb64} is not a 128-bit salt"
            ))),
        }
    }

    /// The blind of update `sn`, derived as keripy derives it (Argon2id of
    /// the hex sequence number, salted with this salt).
    pub fn blind(&self, sn: u64) -> Result<String, RegistryError> {
        derive_uuid(&self.to_qb64(), sn as u128).map_err(format)
    }
}

#[cfg(test)]
mod tests {
    use super::{Blinding, Salt, StateBlock};
    use crate::registry::tests::keripy;

    fn said(text: &str) -> said::SelfAddressingIdentifier {
        text.parse().unwrap()
    }

    /// The blinds and BLIDs keriox derives from keripy's salt are keripy's.
    #[test]
    fn blinded_blocks_are_keripys() {
        let vectors = keripy();
        let salt = Salt::from_qb64(vectors["salt"].as_str().unwrap()).unwrap();
        assert_eq!(salt.to_qb64(), vectors["salt"].as_str().unwrap());
        let acdc = said(vectors["acdc"].as_str().unwrap());
        let blinding = Blinding::Private(salt);
        for update in vectors["updates"].as_array().unwrap() {
            let sn = update["sn"].as_u64().unwrap();
            let state = update["state"].as_str().unwrap();
            let block = StateBlock::new(&blinding, sn, Some(&acdc), state).unwrap();
            assert_eq!(
                block.blid().unwrap().to_string(),
                update["blid"].as_str().unwrap()
            );
        }
        let public = StateBlock::new(&Blinding::Public, 1, Some(&acdc), "issued").unwrap();
        assert_eq!(
            public.blid().unwrap().to_string(),
            vectors["public_block"]["blid"].as_str().unwrap()
        );
    }

    /// A block survives its attachment group, and the Discloser finds the
    /// state behind a BLID from the salt alone.
    #[test]
    fn a_block_is_carried_in_its_group_and_unblinded() {
        let blinding = Blinding::private();
        let acdc = said("EHqSsH1Imc2MEcgzEordBUFqJKWTcRyTz2GRc2SG3aur");
        let block = StateBlock::new(&blinding, 2, Some(&acdc), "revoked").unwrap();
        let group = block.to_group().unwrap();
        assert_eq!(
            StateBlock::parse_group(&group).unwrap(),
            vec![block.clone()]
        );

        let blid = block.blid().unwrap();
        let states = ["issued", "revoked"];
        let found = StateBlock::unblind(&blid, &blinding, 2, &acdc, &states)
            .unwrap()
            .unwrap();
        assert_eq!(found.state(), "revoked");
        assert!(StateBlock::unblind(&blid, &blinding, 1, &acdc, &states)
            .unwrap()
            .is_none());
    }
}
