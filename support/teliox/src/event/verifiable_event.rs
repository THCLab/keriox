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

    /// TEL events with their source seals, from a stream sent by a peer.
    /// A body that is not a TEL event, whose SAID does not match it, or that
    /// comes without a source seal is an error.
    pub fn parse(stream: &[u8]) -> Result<Vec<Self>, Error> {
        let events = keri_core::event_message::cesr_adapter::parse_cesr_stream_many(stream)
            .map_err(|e| Error::Generic(e.to_string()))?;
        events
            .into_iter()
            .map(|ev| -> Result<Self, Error> {
                let event: Event = match &ev.payload {
                    Payload::JSON(body) => serde_json::from_slice(body).map_err(|e| e.to_string()),
                    Payload::CBOR(body) => serde_cbor::from_slice(body).map_err(|e| e.to_string()),
                    Payload::MGPK(body) => rmp_serde::from_slice(body).map_err(|e| e.to_string()),
                    #[allow(unreachable_patterns)]
                    _ => Err("unsupported message body".to_string()),
                }
                .map_err(|e| Error::Generic(format!("not a TEL event: {e}")))?;
                // Signatures and anchors cover keriox's own encoding of the
                // event and its SAID, so the body must re-encode to the same
                // bytes and match its SAID.
                if event.serialize()? != ev.payload.to_vec() {
                    return Err(Error::Generic(
                        "TEL event differs from its canonical serialization".into(),
                    ));
                }
                match &event {
                    Event::Management(man) => man.check_digest(),
                    Event::Vc(vc) => vc.check_digest(),
                }
                .map_err(|_| Error::DigestsNotMatchError)?;
                let seal = match ev.attachments.first().ok_or_else(|| {
                    Error::Generic("TEL event without its source seal".into())
                })? {
                    cesrox::group::Group::SourceSealCouples(seal) => {
                        let couple = seal
                            .first()
                            .ok_or_else(|| Error::Generic("Empty source seal group".into()))?
                            .clone();
                        let sn = u64::try_from(couple.sn).map_err(|_| {
                            Error::Generic(format!("Sequence number {} out of range", couple.sn))
                        })?;
                        Ok(AttachedSourceSeal::new(sn, couple.digest.into()))
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
    let to_parse = r#"{"v":"KERI10JSON000162_","t":"bis","d":"EBHDapxv5R6HDyO-ijNT-lRW8Ft9F9Vv3XIdTIc4z-fk","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","ii":"ECxyKOLIxJM5EO9XFLSzqWI29JusgC9s6-wK16w5jsTs","ra":{"i":"EGeQ8F7zdANw_Nra_WXVBaaGLlRvAJVoJXzQUrKfP8qC","s":"0","d":"EKGKuR7zsPsPd_JiUII8xFcub5_PfUfyZxphTQ08L8L3"},"dt":"2023-06-29T13:15:16.973665+00:00"}-SAB0AAAAAAAAAAAAAAAAAAAAAAgEC6emXzjKLeG08NAMNNIxirnQvJVunkCFkFL-OmprXGh{"v":"KERI10JSON000161_","t":"brv","d":"EEsynyu-azA8vgJ-cbbDmxFZ44UWTncph7Zo6A2RfCW7","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"1","p":"EBHDapxv5R6HDyO-ijNT-lRW8Ft9F9Vv3XIdTIc4z-fk","ra":{"i":"EGeQ8F7zdANw_Nra_WXVBaaGLlRvAJVoJXzQUrKfP8qC","s":"0","d":"EKGKuR7zsPsPd_JiUII8xFcub5_PfUfyZxphTQ08L8L3"},"dt":"2023-06-29T13:15:16.980295+00:00"}-SAB0AAAAAAAAAAAAAAAAAAAAAAwEL5gH12rlRc4br0sGQfok5XiydNlRqlBGrNMrILv5woc"#;
    let parsed = VerifiableEvent::parse(to_parse.as_bytes())?;
    assert_eq!(parsed.len(), 2);
    Ok(())
}

#[cfg(test)]
mod peer_input {
    use super::VerifiableEvent;

    const BIS: &str = r#"{"v":"KERI10JSON000162_","t":"bis","d":"EBHDapxv5R6HDyO-ijNT-lRW8Ft9F9Vv3XIdTIc4z-fk","i":"EEvXZtq623byRrE7h34J7sosXnSlXT5oKMuvntyqTgVa","s":"0","ii":"ECxyKOLIxJM5EO9XFLSzqWI29JusgC9s6-wK16w5jsTs","ra":{"i":"EGeQ8F7zdANw_Nra_WXVBaaGLlRvAJVoJXzQUrKfP8qC","s":"0","d":"EKGKuR7zsPsPd_JiUII8xFcub5_PfUfyZxphTQ08L8L3"},"dt":"2023-06-29T13:15:16.973665+00:00"}"#;
    const SEAL: &str = "-SAB0AAAAAAAAAAAAAAAAAAAAAAgEC6emXzjKLeG08NAMNNIxirnQvJVunkCFkFL-OmprXGh";

    #[test]
    fn a_body_that_is_not_a_tel_event_is_an_error() {
        let icp = r#"{"v":"KERI10JSON00012b_","t":"icp","d":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","i":"EA_SbBUZYwqLVlAAn14d6QUBQCSReJlZ755JqTgmRhXH","s":"0","kt":"1","k":["DKiNnDmdOkcBjcAqL2FFhMZnSlPfNyGrJlCjJmX5b1nU"],"nt":"1","n":["EMP7Lg6BtehOYZt2RwOqXLNfMUiUllejAp8G_5EiANXR"],"bt":"0","b":[],"c":[],"a":[]}"#;
        assert!(VerifiableEvent::parse(format!("{icp}{SEAL}").as_bytes()).is_err());
    }

    #[test]
    fn a_tel_event_without_its_source_seal_is_an_error() {
        assert!(VerifiableEvent::parse(BIS.as_bytes()).is_err());
    }

    #[test]
    fn a_tel_event_whose_said_does_not_match_is_an_error() {
        let altered = BIS.replace("2023-06-29T13:15:16.973665", "2023-06-29T13:15:17.973665");
        assert!(VerifiableEvent::parse(format!("{altered}{SEAL}").as_bytes()).is_err());
        assert!(VerifiableEvent::parse(format!("{BIS}{SEAL}").as_bytes()).is_ok());
    }
}
