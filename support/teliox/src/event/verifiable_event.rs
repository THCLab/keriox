use crate::error::Error;
use crate::seal::AttachedSourceSeal;
use cesrox::payload::Payload;
use serde::{Deserialize, Serialize};

use super::Event;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct VerifiableEvent {
    pub event: Event,
    pub seal: AttachedSourceSeal,
}

impl VerifiableEvent {
    pub fn new(event: Event, seal: AttachedSourceSeal) -> Self {
        Self { event, seal }
    }

    pub fn serialize(&self) -> Result<Vec<u8>, Error> {
        Ok(match &self.event {
            Event::Management(man) => [man.encode()?, self.seal.serialize()?].join("".as_bytes()),
            Event::Vc(vc) => [vc.encode()?, self.seal.serialize()?].join("".as_bytes()),
        })
    }

    pub fn get_event(&self) -> Event {
        self.event.clone()
    }

    pub fn parse(stream: &[u8]) -> Result<Vec<Self>, Error> {
        let events = cesrox::parse_many(stream).unwrap().1;
        events
            .into_iter()
            .map(|ev| -> Result<Self, Error> {
                let event: Event = match ev.payload {
                    Payload::JSON(json) => serde_json::from_slice(&json).unwrap(),
                    _ => todo!(),
                };
                let seal = match &ev.attachments[0] {
                    cesrox::group::Group::SourceSealCouples(seal) => {
                        let (sn, digest) = seal[0].clone();
                        Ok(AttachedSourceSeal::new(sn, (digest.clone()).into()))
                    }
                    _ => Err(Error::Generic("Unexpected attachment".into())),
                }?;
                Ok(Self { event, seal })
            })
            .collect()
    }
}

#[test]
fn test_parse() -> Result<(), Error> {
    let to_parse = r#"{"v":"KERI10JSON000162_","t":"bis","d":"EBHDapxv5R6HDyO-ijNT-lRW8Ft9F9Vv3XIdTIc4z-fk","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","ii":"ECxyKOLIxJM5EO9XFLSzqWI29JusgC9s6-wK16w5jsTs","ra":{"i":"EGeQ8F7zdANw_Nra_WXVBaaGLlRvAJVoJXzQUrKfP8qC","s":"0","d":"EKGKuR7zsPsPd_JiUII8xFcub5_PfUfyZxphTQ08L8L3"},"dt":"2023-06-29T13:15:16.973665+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAgEC6emXzjKLeG08NAMNNIxirnQvJVunkCFkFL-OmprXGh{"v":"KERI10JSON000161_","t":"brv","d":"EEsynyu-azA8vgJ-cbbDmxFZ44UWTncph7Zo6A2RfCW7","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","p":"EBHDapxv5R6HDyO-ijNT-lRW8Ft9F9Vv3XIdTIc4z-fk","ra":{"i":"EGeQ8F7zdANw_Nra_WXVBaaGLlRvAJVoJXzQUrKfP8qC","s":"0","d":"EKGKuR7zsPsPd_JiUII8xFcub5_PfUfyZxphTQ08L8L3"},"dt":"2023-06-29T13:15:16.980295+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAAwEL5gH12rlRc4br0sGQfok5XiydNlRqlBGrNMrILv5woc"#;
    let parsed = VerifiableEvent::parse(to_parse.as_bytes())?;
    assert_eq!(parsed.len(), 2);
    Ok(())
}
