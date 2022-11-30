pub mod codes;
pub mod error;
pub mod parsers;
pub mod primitives;

use self::error::Error;

use self::group::Group;

pub mod group;
pub mod parsing;
pub mod path;
pub mod value;

pub trait Payload {
    fn to_vec(&self) -> Result<Vec<u8>, Error>;
}
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedData<P> {
    pub payload: P,
    pub attachments: Vec<Group>,
}

impl<P: Payload> ParsedData<P> {
    pub fn to_cesr(&self) -> Result<Vec<u8>, Error> {
        let attachments = self
            .attachments
            .iter()
            .fold(String::default(), |acc, att| {
                [acc, att.to_cesr_str()].concat()
            })
            .as_bytes()
            .to_vec();
        Ok([self.payload.to_vec()?, attachments].concat())
    }
}
