//! What a Discloser presents of a credential: the ACDC and the disclosure of
//! its registry, as one CESR stream. The ACDC and every registry event carry
//! their own version string and size, and the head's state block follows in
//! its attachment group, so the stream needs no other framing.

use acdc::{message::Message, Acdc};
use said::SelfAddressingIdentifier;

use super::{issuer::Disclosure, AcdcBinding, RegistryError, RegistryMessage, StateBlock};

fn format(e: impl std::fmt::Display) -> RegistryError {
    RegistryError::Format(e.to_string())
}

#[derive(Debug, Clone, PartialEq)]
pub struct Presentation {
    pub acdc: Acdc,
    pub disclosure: Disclosure,
}

impl Presentation {
    /// What the ACDC says about itself, to bind it to its registry.
    pub fn binding(&self) -> Result<AcdcBinding, RegistryError> {
        let said = |text: &str| {
            text.parse::<SelfAddressingIdentifier>()
                .map_err(|_| RegistryError::Format(format!("{text} is not a SAID")))
        };
        Ok(AcdcBinding {
            said: said(self.acdc.said())?,
            issuer: self
                .acdc
                .issuer()
                .parse()
                .map_err(|_| RegistryError::Format("ACDC issuer is not an AID".into()))?,
            registry: self.acdc.registry().map(said).transpose()?,
        })
    }

    /// The ACDC, the registry events from its inception, and the head's
    /// state block.
    pub fn to_cesr(&self) -> Result<Vec<u8>, RegistryError> {
        let mut out = self.acdc.raw().to_vec();
        for event in std::iter::once(&self.disclosure.inception).chain(&self.disclosure.updates) {
            out.extend(event.encode());
        }
        if let Some(block) = &self.disclosure.block {
            out.extend(block.to_group()?.into_bytes());
        }
        Ok(out)
    }

    pub fn parse(mut bytes: &[u8]) -> Result<Self, RegistryError> {
        let (message, size) = Message::parse(bytes).map_err(format)?;
        let Message::Acdc(acdc) = message else {
            return Err(RegistryError::Format(
                "a presentation starts with the ACDC".into(),
            ));
        };
        bytes = &bytes[size..];
        let mut events = vec![];
        while !bytes.is_empty() && bytes[0] != b'-' {
            let (_, size) = Message::parse(bytes).map_err(format)?;
            events.push(RegistryMessage::parse(&bytes[..size])?);
            bytes = &bytes[size..];
        }
        let block = match bytes {
            [] => None,
            group => {
                let text = std::str::from_utf8(group)
                    .map_err(|_| RegistryError::Format("the state block is not text".into()))?;
                match StateBlock::parse_group(text)?.as_slice() {
                    [block] => Some(block.clone()),
                    _ => {
                        return Err(RegistryError::Format(
                            "a presentation carries one state block".into(),
                        ))
                    }
                }
            }
        };
        let mut events = events.into_iter();
        let inception = events
            .next()
            .ok_or_else(|| RegistryError::Format("a presentation has no registry".into()))?;
        Ok(Presentation {
            acdc: *acdc,
            disclosure: Disclosure {
                inception,
                updates: events.collect(),
                block,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use acdc::{Acdc, Block, HashFunctionCode, Kind};

    use super::Presentation;
    use crate::registry::{
        verify::tests::Issuer, Binding, Blinding, MemoryRegistryStore, Policy, RegistryIssuer,
        Validator, Verdict,
    };

    /// A credential naming its registry is incepted and issued under one
    /// anchor, presented as one stream, and judged valid and mutually bound
    /// from that stream alone.
    #[test]
    fn a_presented_credential_verifies_from_its_stream() {
        let mut issuer = Issuer::new();
        let registrar = RegistryIssuer::new(MemoryRegistryStore::new());
        let blinding = Blinding::private();
        let rip = registrar.incept(&issuer.id).unwrap();
        let registry = rip.event.said().unwrap();
        let acdc = Acdc::builder(
            issuer.id.to_string(),
            "EOlgQaGgXI6Zqikg4I0KWaQeL9sRUGu7PUj78GekKnSf",
        )
        .private()
        .registry(registry.to_string())
        .attributes(Block::new().private().with("name", "Zoe Doe"))
        .build(Kind::Json, HashFunctionCode::Blake3_256)
        .unwrap();
        let issued = registrar
            .issue_after(&rip, &blinding, &acdc.said().parse().unwrap())
            .unwrap();
        issuer.anchor(vec![rip.seal().unwrap(), issued.seal().unwrap()]);
        registrar.commit(&rip).unwrap();
        registrar.commit(&issued).unwrap();

        let presented = Presentation {
            acdc,
            disclosure: registrar.disclosure(&registry).unwrap(),
        };
        let stream = presented.to_cesr().unwrap();
        let received = Presentation::parse(&stream).unwrap();
        assert_eq!(received, presented);

        let validator = Validator::new(MemoryRegistryStore::new(), Policy::default());
        let binding = received.binding().unwrap();
        let verdict = validator
            .accept(&issuer.storage, &received.disclosure, Some(&binding))
            .unwrap();
        let Verdict::Valid { state, .. } = verdict else {
            panic!("{verdict:?}")
        };
        assert_eq!(state.state.as_deref(), Some("issued"));
        assert_eq!(state.binding, Some(Binding::Mutual));
        assert!(Presentation::parse(&stream[..stream.len() - 1]).is_err());
    }
}
