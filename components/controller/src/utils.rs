use std::path::PathBuf;

use keri::oobi::LocationScheme;

pub struct OptionalConfig {
    pub db_path: Option<PathBuf>,
    pub initial_oobis: Option<Vec<LocationScheme>>,
}

impl OptionalConfig {
    pub fn init() -> Self {
        Self {
            db_path: None,
            initial_oobis: None,
        }
    }

    pub fn with_initial_oobis(self, oobis: Vec<LocationScheme>) -> Self {
        Self {
            initial_oobis: Some(oobis),
            ..self
        }
    }
    pub fn with_db_path(self, db_path: PathBuf) -> Self {
        Self {
            db_path: Some(db_path),
            ..self
        }
    }
}
