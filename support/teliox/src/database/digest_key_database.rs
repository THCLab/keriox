use std::sync::Arc;

use redb::MultimapTableDefinition;
use said::SelfAddressingIdentifier;

use crate::error::Error;


pub struct DigestKeyDatabase {
    pub db: Arc<redb::Database>,
    /// Escrowed events. KEL event digest -> TEL event digest
    /// Table links a missing KEL event digest to the digest of TEL event.
    digest_key_table: MultimapTableDefinition<'static, &'static str, &'static str>,
}

impl DigestKeyDatabase {
    pub fn new(db: Arc<redb::Database>) -> Self {
        let digest_key_table = MultimapTableDefinition::new("missing_issuer_escrow");

        Self {
            db,
            digest_key_table,
        }
    }

    pub fn insert(
        &self,
        id: &SelfAddressingIdentifier,
        event_digest: SelfAddressingIdentifier,
    ) -> Result<(), Error> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_multimap_table(self.digest_key_table)?;
            let key = id.to_string();
            let value = event_digest.to_string();

            table.insert(&key.as_str(), value.as_str())?;
        }
        tx.commit()?;

        Ok(())
    }

    pub fn get(&self, digest: &SelfAddressingIdentifier) -> Result<Vec<SelfAddressingIdentifier>, Error> {
        let tx = self.db.begin_read()?;
        let table = tx.open_multimap_table(self.digest_key_table)?;
        let key = digest.to_string();

        let out = table.get(&key.as_str())
            .unwrap()
            .map(|val| {
                let said = val.unwrap();
                said.value().parse().unwrap()
            }).collect();
        Ok(out)
    }

    pub fn remove(&self, digest: &SelfAddressingIdentifier, kel_ev_digest: &SelfAddressingIdentifier) -> Result<(), Error> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_multimap_table(self.digest_key_table)?;
            let key = digest.to_string();
            table.remove(&key.as_str(), kel_ev_digest.to_string().as_str())?;
        }
        tx.commit()?;
        Ok(())
    }
}
