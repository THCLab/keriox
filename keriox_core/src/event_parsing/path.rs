use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct MaterialPath {
	pub path: String
}

impl MaterialPath {
	pub fn new(path: String) -> Self {
		todo!()
	}

}