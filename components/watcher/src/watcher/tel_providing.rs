use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use keri_core::prefix::IdentifierPrefix;

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    #[error("Value parse error: {0}")]
    ValueParsing(String),
}
struct Store(PathBuf);

trait StoreKey {
    fn key(&self) -> String;
}

struct VCKey {
    ri: IdentifierPrefix,
    vc_id: IdentifierPrefix,
}

impl StoreKey for VCKey {
    fn key(&self) -> String {
        [self.ri.to_string(), self.vc_id.to_string()].join(",")
    }
}

impl Store {
    pub fn new(path: PathBuf) -> Result<Self, StoreError> {
        // Create file if doesn't exist.
        let _file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        Ok(Store(path))
    }

    fn get<K: StoreKey>(&self, key: &K) -> Result<Option<String>, StoreError> {
        let br = BufReader::new(File::open(&self.0)?);
        let out = br.lines().filter_map(|line| line.ok()).find_map(|line| {
            if line.contains(&key.key()) {
                let mut splitted = line.splitn(2, ":");
                let _key = splitted.next();
                let value = splitted.next();
                value.map(|el| el.to_string())
            } else {
                None
            }
        });
        Ok(out.map(|el| el.to_string()))
    }

    pub fn save<K: StoreKey>(&self, key: K, value: String) -> Result<(), StoreError> {
        let lines = {
            let br = BufReader::new(File::open(&self.0)?);
            br.lines()
        };

        let mut found = false;
        let new_lines = lines.filter_map(|line| {
            line.map(|l| {
                if l.contains(&key.key()) {
                    let new_line = format!("{}:{}", key.key(), value);
                    found = true;
                    new_line
                } else {
                    l
                }
            })
            .ok()
        });
        let new_contents = {
            let new_contents = new_lines.fold(String::new(), |a, b| a + &b + "\n");
            if !found {
                [new_contents, format!("{}:{}", key.key(), value)].join("")
            } else {
                new_contents
            }
        };

        let mut f = fs::File::create(&self.0).expect("no file found");
        f.write_all(new_contents.as_bytes())?;
        Ok(())
    }
}

/// Struct for storing TEL events which were collected from witnesses for
/// identifier. Watcher doesn't check provided TEL events, just save them and
/// forward to recipient when it sends query message.
pub(super) struct TelToForward {
    /// The key is a tuple of Registry identifiers nad Vc identifier, and the
    /// value is collected TEL events
    tel: Store,
}

impl TelToForward {
    pub fn new(path: PathBuf) -> Result<Self, StoreError> {
        let store = Store::new(path)?;

        Ok(Self { tel: store })
    }

    pub fn save(
        &self,
        about_ri: IdentifierPrefix,
        about_vc_id: IdentifierPrefix,
        tel: String,
    ) -> Result<(), StoreError> {
        let vc_key = VCKey {
            ri: about_ri,
            vc_id: about_vc_id,
        };
        self.tel.save(vc_key, tel)
    }

    pub fn get(
        &self,
        ri: IdentifierPrefix,
        vc_id: IdentifierPrefix,
    ) -> Result<Option<String>, StoreError> {
        let vc_key = VCKey { ri, vc_id };
        self.tel.get(&vc_key)
    }
}

impl StoreKey for IdentifierPrefix {
    fn key(&self) -> String {
        self.to_string()
    }
}

/// Struct for saving mapping between Registry Identifier and identifier of
/// entity that stores corresponding TEL events. (Usually witness identifier).
/// Those are provided to watcher by identifier using oobi.
pub(super) struct RegistryMapping {
    /// Key is registry identifier, and value is witness identifier.
    mapping: Store,
}

impl RegistryMapping {
    pub fn new(path: &Path) -> Result<Self, StoreError> {
        Ok(Self {
            mapping: Store::new(path.to_path_buf())?,
        })
    }
    pub fn save(&self, key: IdentifierPrefix, value: IdentifierPrefix) -> Result<(), StoreError> {
        self.mapping.save(key, value.to_string())?;
        Ok(())
    }

    pub fn get(&self, key: &IdentifierPrefix) -> Result<Option<IdentifierPrefix>, StoreError> {
        self.mapping
            .get(key)?
            .map(|id| id.parse().map_err(|_e| StoreError::ValueParsing(id)))
            .transpose()
    }
}
