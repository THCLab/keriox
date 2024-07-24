use std::{collections::HashMap, fs::{self, create_dir_all, File, OpenOptions}, io::{BufRead, BufReader, Write}, path::{Path, PathBuf}, sync::Mutex};

use keri_core::{error::Error, prefix::IdentifierPrefix};

#[derive(thiserror::Error, Debug)]
pub enum StoreError {
    #[error(transparent)]
    FileError(#[from] std::io::Error)
}
struct Store(PathBuf);

impl Store {
    pub fn new(path: PathBuf) -> Self {
        // Create file if doesn't exist.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path).unwrap();
        println!("\ncreated: {}", &path.to_str().unwrap()); 
        Store(path)
    }

    fn get(&self, key: (IdentifierPrefix, IdentifierPrefix)) -> Result<Option<String>, StoreError> {
        let br = BufReader::new(File::open(&self.0)?);
        let out = br.lines().filter_map(|line| line.ok())
        .find_map(|line| 
            if line.contains(&format!("{},{}", key.0, key.1)) {
                let mut splitted = line.splitn(2, ":");
                let _key = splitted.next();
                let value = splitted.next();
                value.map(|el| el.to_string())
            } else {
                None
            }
        );
        Ok(out.map(|el| el.to_string()))
    }

    pub fn save(&self, key: (IdentifierPrefix, IdentifierPrefix), value: String) {

        let lines = {
            let br = BufReader::new(File::open(&self.0).unwrap());
            br.lines()
        };

        let mut found = false;
        let new_lines = lines.map(|line| {
            if line.as_ref().unwrap().contains(&format!("{},{}", key.0, key.1)) {
                let new_line = format!("{},{}:{}", key.0, key.1,value);
                found = true;
                new_line
            } else {
                line.unwrap()
            }
        });
        let new_contents = {
            let new_contents = new_lines.fold(String::new(), |a, b| a + &b + "\n");
            if !found {
                    [new_contents, format!("{},{}:{}", key.0, key.1, value)].join("")
                } else {
                    new_contents
                } 
            };

        let mut f = fs::File::create(&self.0).expect("no file found");
        f.write_all(new_contents.as_bytes()).unwrap();



    }
}

/// Struct for storing TEL events which were collected from witnesses for
/// identifier. Watcher doesn't check provided TEL events, just save them and
/// forward to recipient when it sends query message.
pub(super) struct TelToForward {
    /// The key is a tuple of Registry identifiers nad Vc idettifier, and the
    /// value is collected TEL events
    tel: Mutex<Store>,
}

impl TelToForward {
    pub fn new(path: PathBuf) -> Self {
        let store = Store::new(path);

        Self {
            tel: Mutex::new(store),
        }
    }

    pub fn save(&self, about_ri: IdentifierPrefix, about_vc_id: IdentifierPrefix, tel: String) {
        let saving = self.tel.lock().unwrap();
        saving.save((about_ri.clone(), about_vc_id.clone()), tel);
    }

    pub fn get(&self, ri: IdentifierPrefix, vc_id: IdentifierPrefix) -> Result<Option<String>, StoreError> {
        let saving = self.tel.lock().unwrap();
        saving.get((ri, vc_id))
    }
}

/// Struct for saving mapping between Registry Identifier and identifier of
/// entity that stores corresponding TEL events. (Usually witness identifier).
/// Those are provided to watcher by identifier using oobi.
pub(super) struct RegistryMapping {
    /// Key is registry identifier, and value is witness identifier.
    mapping: Mutex<HashMap<IdentifierPrefix, IdentifierPrefix>>,
}

impl RegistryMapping {
    pub fn new() -> Self {
        Self {
            mapping: Mutex::new(HashMap::new()),
        }
    }
    pub fn save(&self, key: IdentifierPrefix, value: IdentifierPrefix) -> Result<(), Error> {
        let mut data = self.mapping.lock().unwrap();
        data.insert(key, value);
        Ok(())
    }

    pub fn get(&self, key: &IdentifierPrefix) -> Option<IdentifierPrefix> {
        let data = self.mapping.lock().unwrap();
        data.get(key).map(|id| id.clone())
    }
}
