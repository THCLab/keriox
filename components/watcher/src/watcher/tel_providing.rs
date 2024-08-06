use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};

use keri_core::prefix::IdentifierPrefix;
use regex::Regex;

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error(transparent)]
    FileError(#[from] std::io::Error),
    #[error("Value parse error: {0}")]
    ValueParsing(String),
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}
struct Store(PathBuf);

trait StoreKey {
    fn key(&self) -> String;
}

struct VCKey<'a> {
    ri: &'a IdentifierPrefix,
    vc_id: &'a IdentifierPrefix,
}

impl<'a> StoreKey for VCKey<'a> {
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

    fn find_event_types<'a>(tel_stream: &'a str) -> Result<Vec<String>, StoreError> {
        let re = Regex::new(r#""t":"(vcp|bis|brv)"#)
            .map_err(|_e| StoreError::Unexpected("Invalid regex".to_string()))?;
        Ok(re
            .captures_iter(tel_stream)
            .map(|c| c.extract())
            .map(|(_, [s])| s.to_string())
            .collect())
    }

    pub fn save(
        &self,
        about_ri: &IdentifierPrefix,
        about_vc_id: &IdentifierPrefix,
        tel: String,
    ) -> Result<(), StoreError> {
        let already_saved = self.get(about_ri, about_vc_id)?;
        let db_sns = match already_saved {
            Some(saved) => TelToForward::find_event_types(&saved)?,
            None => vec![],
        };
        let re = Regex::new(r#""t":"(vcp|bis|brv)"#)
            .map_err(|_e| StoreError::Unexpected("Invalid regex".to_string()))?;
        let mut got = re
            .captures_iter(&tel)
            .map(|c| c.extract())
            .map(|(_, [s])| s.to_string());

        let up_to_date = got.all(|el| db_sns.contains(&el));
        if !up_to_date {
            let vc_key = VCKey {
                ri: about_ri,
                vc_id: about_vc_id,
            };
            self.tel.save(vc_key, tel)?;
        };
        Ok(())
    }

    pub fn get(
        &self,
        ri: &IdentifierPrefix,
        vc_id: &IdentifierPrefix,
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

#[test]
fn test_tel_to_forward() {
    let tmp_file = tempfile::NamedTempFile::new().unwrap();

    let path = tmp_file.path().to_path_buf();
    let tel_to_forward = TelToForward::new(path).unwrap();
    let registry_id: IdentifierPrefix = "EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH"
        .parse()
        .unwrap();
    let vc_id: IdentifierPrefix = "ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k"
        .parse()
        .unwrap();
    let full_tel = r#"{"v":"KERI10JSON0000e0_","t":"vcp","d":"ELKXqawms-uIvL74BTnYHFOPJrjD8N9DaC2-Yljl_OOn","i":"EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH","s":"0","ii":"EL2KqdbeSkemPII22qQ9dNglhBYa2YaQL7ePjN-3aTGg","c":["NB"],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAABEKK6lIEGR6MEuweYBwtiQb6giHxj-nvX4uwQY0tOj1KQ{"v":"KERI10JSON000162_","t":"bis","d":"EDoj2ic6WlRrszgT3Hm67-fdxjr-ZxRZMy9O9MXURZDF","i":"ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k","s":"0","ii":"EL2KqdbeSkemPII22qQ9dNglhBYa2YaQL7ePjN-3aTGg","ra":{"i":"EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH","s":"0","d":"ELKXqawms-uIvL74BTnYHFOPJrjD8N9DaC2-Yljl_OOn"},"dt":"2024-08-01T11:55:26.509238+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAACEHUKCdWrjC14xuBc2wMgVlF0zmyhx5XXTtjZC7GVtQ2f{"v":"KERI10JSON000161_","t":"brv","d":"EI6P1iV3bSFI5Y_TEhep-uvrGXxwFVdixPjvLKLRP7Oy","i":"ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k","s":"1","p":"EDoj2ic6WlRrszgT3Hm67-fdxjr-ZxRZMy9O9MXURZDF","ra":{"i":"EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH","s":"0","d":"ELKXqawms-uIvL74BTnYHFOPJrjD8N9DaC2-Yljl_OOn"},"dt":"2024-08-01T11:55:28.579999+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAADEO0smZufH8Yrtl6ac_iqF2QeBCJmT031wYqlEMKbeROV"#;
    let not_full_tel = r#"{"v":"KERI10JSON0000e0_","t":"vcp","d":"ELKXqawms-uIvL74BTnYHFOPJrjD8N9DaC2-Yljl_OOn","i":"EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH","s":"0","ii":"EL2KqdbeSkemPII22qQ9dNglhBYa2YaQL7ePjN-3aTGg","c":["NB"],"bt":"0","b":[]}-GAB0AAAAAAAAAAAAAAAAAAAAAABEKK6lIEGR6MEuweYBwtiQb6giHxj-nvX4uwQY0tOj1KQ{"v":"KERI10JSON000162_","t":"bis","d":"EDoj2ic6WlRrszgT3Hm67-fdxjr-ZxRZMy9O9MXURZDF","i":"ENdJge-nCgyIC42MGYXQddvL9nm5ml-ZFOWq-WuDGp4k","s":"0","ii":"EL2KqdbeSkemPII22qQ9dNglhBYa2YaQL7ePjN-3aTGg","ra":{"i":"EEJeOc0HPZScDMKD-L9RsJ9K5-j73IZkMA2tui5gYEpH","s":"0","d":"ELKXqawms-uIvL74BTnYHFOPJrjD8N9DaC2-Yljl_OOn"},"dt":"2024-08-01T11:55:26.509238+00:00"}-GAB0AAAAAAAAAAAAAAAAAAAAAACEHUKCdWrjC14xuBc2wMgVlF0zmyhx5XXTtjZC7GVtQ2f"#;

    tel_to_forward
        .save(&registry_id, &vc_id, full_tel.to_string())
        .unwrap();
    let saved = tel_to_forward.get(&registry_id, &vc_id).unwrap();
    assert_eq!(saved.as_ref(), Some(full_tel.to_string()).as_ref());

    // Try to save only subset of TEL events. Should not be replaced.
    tel_to_forward
        .save(&registry_id, &vc_id, not_full_tel.to_string())
        .unwrap();
    assert_eq!(saved.as_ref(), Some(full_tel.to_string()).as_ref());
}
