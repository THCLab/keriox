use std::{sync::{Arc, Mutex}, collections::VecDeque};

#[cfg(feature = "wallet")]
use universal_wallet::prelude::{Content, UnlockedWallet};

use crate::{database::sled::SledEventDatabase, error::Error, prefix::{IdentifierPrefix, BasicPrefix, AttachedSignaturePrefix}, derivation::{basic::Basic, self_signing::SelfSigning}, keys::PublicKey, processor::{EventProcessor, event_storage::EventStorage}, signer::KeyManager, event_message::{signed_event_message::{SignedEventMessage, Message}, event_msg_builder::EventMsgBuilder, EventTypeTag}};

use super::Keri;

#[cfg(feature = "wallet")]
impl Keri<UnlockedWallet> {
    /// Instantiates KERI with freshly created and pre-populated wallet
    /// Wallet has ECDSA and X25519 key pairs
    /// Only available with crate `wallet` feature.
    ///
    pub fn new_with_fresh_wallet(
        db: Arc<SledEventDatabase>,
    ) -> Result<Keri<UnlockedWallet>, Error> {
        use crate::{
            prefix::Prefix,
            signer::wallet::{incept_keys, CURRENT},
        };
        // instantiate wallet with random ID instead of static for security reasons
        let mut wallet = UnlockedWallet::new(&generate_random_string());
        incept_keys(&mut wallet)?;
        let pk = match wallet.get_key(CURRENT).unwrap().content {
            Content::PublicKey(pk) => pk.public_key,
            Content::KeyPair(kp) => kp.public_key.public_key,
            Content::Entropy(_) => {
                return Err(Error::WalletError(universal_wallet::Error::KeyNotFound))
            }
        };
        let prefix =
            IdentifierPrefix::Basic(BasicPrefix::new(Basic::ECDSAsecp256k1, PublicKey::new(pk)));
        // setting wallet's ID to prefix of identity instead of random string
        wallet.id = prefix.to_str();
        Ok(Keri {
            prefix,
            key_manager: Arc::new(Mutex::new(wallet)),
            processor: EventProcessor::with_default_escrow(db.clone()),
            storage: EventStorage::new(db),
            response_queue: VecDeque::new(),
        })
    }
}

impl<K: KeyManager> Keri<K> {
 /// Incepts instance of KERI and includes EXTRA keys provided as parameter
    /// CURRENT Public verification key is extracted directly from KeyManager
    ///  - it should not be included into `extra_keys` set.
    /// # Parameters
    /// * `extra_keys` - iterator over tuples of `(keri::derivation::Basic, keri::keys::Key)`
    /// # Returns
    /// `Result<keri::event_message::SignedEventMessage, keri::error::Error>`
    ///  where `SignedEventMessage` is ICP event including all provided keys + directly fetched
    ///  verification key, signed with it's private key via KeyManager and serialized.
    ///
    pub fn incept_with_extra_keys(
        &mut self,
        extra_keys: impl IntoIterator<Item = (Basic, PublicKey)>,
    ) -> Result<SignedEventMessage, Error> {
        let mut keys: Vec<BasicPrefix> = extra_keys
            .into_iter()
            .map(|(key_type, key)| key_type.derive(key))
            .collect();
        // Signing key must be first
        let km = self.key_manager.lock().map_err(|_| Error::MutexPoisoned)?;
        keys.insert(0, Basic::Ed25519.derive(km.public_key()));
        let icp = EventMsgBuilder::new(EventTypeTag::Icp)
            .with_prefix(&self.prefix)
            .with_keys(keys)
            .with_next_keys(vec![Basic::Ed25519.derive(km.next_public_key())])
            .build()?;

        let signed = icp.sign(
            vec![AttachedSignaturePrefix::new(
                SelfSigning::Ed25519Sha512,
                km.sign(&icp.serialize()?)?,
                0,
            )],
            None,
        );
        self.processor.process(Message::Event(signed.clone()))?;
        self.prefix = icp.event.get_prefix();

        Ok(signed)
    }
}

// Non re-allocating random `String` generator with output length of 10 char string
#[cfg(feature = "wallet")]
fn generate_random_string() -> String {
    use rand::Rng;
    const ALL: [char; 61] = [
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R',
        'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
        'k', 'l', 'm', 'n', 'o', 'p', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '9', '8',
        '7', '6', '5', '4', '3', '2', '1',
    ];
    let mut ret = String::default();
    for _ in 0..10 {
        let n = rand::thread_rng().gen_range(0, ALL.len());
        ret.push(ALL[n]);
    }
    ret
}

#[cfg(test)]
#[cfg(feature = "wallet")]
mod keri_wallet {
    #[test]
    fn random_string_test() {
        let rst = super::generate_random_string();
        assert!(!rst.is_empty());
        assert!(rst != super::generate_random_string());
    }
}
