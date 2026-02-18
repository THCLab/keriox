use cesrox::primitives::CesrPrimitive;
use said::{derivation::HashFunction, SelfAddressingIdentifier};
use serde::{Deserialize, Serialize};

use super::threshold::SignatureThreshold;
use crate::{
    database::rkyv_adapter::said_wrapper::SaidValue,
    prefix::{attached_signature::Index, BasicPrefix, IndexedSignature},
};

#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Default,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]

pub struct NextKeysData {
    #[serde(rename = "nt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "n")]
    next_key_hashes: Vec<SaidValue>,
}

impl NextKeysData {
    pub fn new(
        threshold: SignatureThreshold,
        next_keys_hashes: impl IntoIterator<Item = SelfAddressingIdentifier>,
    ) -> Self {
        let next_keys = next_keys_hashes
            .into_iter()
            .map(|said| said.into())
            .collect();
        Self {
            threshold,
            next_key_hashes: next_keys,
        }
    }

    pub fn next_keys_hashes(&self) -> Vec<SelfAddressingIdentifier> {
        self.next_key_hashes
            .clone()
            .into_iter()
            .map(|said| said.into())
            .collect()
    }

    /// Checks if next KeyConfig contains enough public keys to fulfill current
    /// next threshold.
    pub fn verify_next(&self, next: &KeyConfig) -> Result<bool, SignatureError> {
        let indexes: Vec<_> = next
            .public_keys
            .iter()
            .filter_map(|key| {
                self.next_key_hashes
                    .iter()
                    .position(|dig| dig.said.verify_binding(key.to_str().as_bytes()))
            })
            .collect();

        // check previous next threshold
        self.threshold.enough_signatures(&indexes)?;
        Ok(true)
    }

    /// Checks if public keys corresponding to signatures match keys committed in
    /// NextKeysData and if it's enough of them
    pub fn check_threshold<'a>(
        &self,
        public_keys: &[BasicPrefix],
        indexes: impl IntoIterator<Item = &'a Index>,
    ) -> Result<(), SignatureError> {
        // Get indexes of keys in previous next key list.
        let indexes_in_last_prev = self.matching_previous_indexes(public_keys, indexes);

        // Check previous next threshold
        self.threshold.enough_signatures(&indexes_in_last_prev)?;

        Ok(())
    }

    /// Checks if hashes of public keys match public keys of provided indexes.
    /// Returns list of positions in next keys list that matches.
    fn matching_previous_indexes<'a>(
        &self,
        public_keys: &[BasicPrefix],
        indexes: impl IntoIterator<Item = &'a Index>,
    ) -> Vec<usize> {
        // Get indexes of keys in previous next key list.
        indexes
            .into_iter()
            .filter_map(|index| {
                index.previous_next().and_then(|prev_next| {
                    match (
                        self.next_key_hashes.get(prev_next as usize),
                        public_keys.get(index.current() as usize),
                    ) {
                        (Some(prev_next_digest), Some(current)) => prev_next_digest
                            .said
                            .verify_binding(current.to_str().as_bytes())
                            .then_some(prev_next as usize),
                        _ => None,
                    }
                })
            })
            .collect::<Vec<_>>()
    }
}

#[derive(thiserror::Error, Debug, Serialize, Deserialize)]
pub enum SignatureError {
    #[error("Not enough signatures while verifying")]
    NotEnoughSigsError,

    #[error("Signature duplicate while verifying")]
    DuplicateSignature,

    #[error("Too many signatures while verifying")]
    TooManySignatures,

    #[error("Key index not present in the set")]
    MissingIndex,

    #[error("Wrong signature type error")]
    WrongSignatureTypeError,

    #[error("Wrong key type error")]
    WrongKeyTypeError,
}
#[derive(
    Serialize,
    Deserialize,
    Debug,
    Clone,
    Default,
    PartialEq,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct KeyConfig {
    #[serde(rename = "kt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "k")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(flatten)]
    pub next_keys_data: NextKeysData,
}

impl KeyConfig {
    pub fn new(
        public_keys: Vec<BasicPrefix>,
        next_keys_data: NextKeysData,
        threshold: Option<SignatureThreshold>,
    ) -> Self {
        Self {
            threshold: threshold.map_or_else(
                || SignatureThreshold::Simple(public_keys.len() as u64 / 2 + 1),
                |t| t,
            ),
            public_keys,
            next_keys_data,
        }
    }

    /// Verify
    ///
    /// Verifies the given sigs against the given message using the KeyConfigs
    /// Public Keys, according to the indexes in the sigs.
    pub fn verify(
        &self,
        message: &[u8],
        sigs: &[IndexedSignature],
    ) -> Result<bool, SignatureError> {
        // there are no duplicates
        if !(sigs
            .iter()
            .fold(vec![0u64; self.public_keys.len()], |mut acc, sig| {
                acc[sig.index.current() as usize] += 1;
                acc
            })
            .iter()
            .all(|n| *n <= 1))
        {
            Err(SignatureError::DuplicateSignature.into())
        } else if
        // check if there are not too many
        sigs.len() > self.public_keys.len() {
            Err(SignatureError::TooManySignatures.into())

        // ensure there's enough sigs
        } else {
            self.threshold.enough_signatures(
                &sigs
                    .iter()
                    .map(|sig| sig.index.current() as usize)
                    .collect::<Vec<_>>(),
            )?;

            sigs.iter()
                .fold(Ok(true), |acc: Result<bool, SignatureError>, sig| {
                    let verification_result: bool = self
                        .public_keys
                        .get(sig.index.current() as usize)
                        .ok_or_else(|| SignatureError::from(SignatureError::MissingIndex))
                        .and_then(|key: &BasicPrefix| Ok(key.verify(message, &sig.signature)?))?;
                    Ok(acc? && verification_result)
                })
        }
    }

    /// Verify Next
    ///
    /// Verifies that the given next KeyConfig matches that which is committed
    /// to in next_keys_data of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> Result<bool, SignatureError> {
        self.next_keys_data.verify_next(next)
    }

    /// Serialize For Next
    ///
    /// Serializes the KeyConfig for creation or verification of a threshold
    /// key digest commitment
    pub fn commit(&self, derivation: &HashFunction) -> NextKeysData {
        nxt_commitment(self.threshold.clone(), &self.public_keys, derivation)
    }
}

/// Serialize For Commitment
///
/// Creates NextKeysData from given threshold and public keys set.
pub fn nxt_commitment(
    threshold: SignatureThreshold,
    keys: &[BasicPrefix],
    derivation: &HashFunction,
) -> NextKeysData {
    let next_key_hashes = keys
        .iter()
        .map(|bp| derivation.derive(bp.to_str().as_bytes()).into())
        .collect();
    NextKeysData {
        threshold,
        next_key_hashes,
    }
}

#[cfg(test)]
mod test {
    use cesrox::{parse, primitives::CesrPrimitive};
    use said::{derivation::HashFunction, derivation::HashFunctionCode};

    use crate::{
        error::Error,
        event::sections::{
            key_config::{nxt_commitment, NextKeysData, SaidValue, SignatureError},
            threshold::SignatureThreshold,
            KeyConfig,
        },
        prefix::{attached_signature::Index, BasicPrefix, IndexedSignature},
    };

    #[test]
    fn test_next_commitment() {
        // test data taken from keripy
        // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
        // Set weighted threshold to [1/2, 1/2, 1/2]
        let sith = SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
        let next_keys: Vec<BasicPrefix> = [
            "DHqJ2DNmypwMKelWXLgl3V-9pDRcOenM5Wf03O1xx1Ri",
            "DEIISiMvtnaPTpMHkoGs4d0JdbwjreW53OUBfMedLUaF",
            "DDQFJ_uXcZum_DY6NNTtI5UrTEQo6PRWEANpn6hVtfyQ",
        ]
        .iter()
        .map(|x| x.parse().unwrap())
        .collect();
        let nxt = nxt_commitment(sith, &next_keys, &HashFunctionCode::Blake3_256.into());

        let threshold = SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
        let next_key_hashes: Vec<SaidValue> = [
            "EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy",
            "ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p",
            "EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH",
        ]
        .iter()
        .map(|sai| SaidValue {
            said: sai.parse().unwrap(),
        })
        .collect();

        assert_eq!(
            nxt,
            NextKeysData {
                threshold,
                next_key_hashes,
            }
        );
    }

    #[test]
    fn test_threshold() -> Result<(), Error> {
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        use crate::{
            keys::{PrivateKey, PublicKey},
            prefix::SelfSigningPrefix,
        };

        let (pub_keys, priv_keys): (Vec<BasicPrefix>, Vec<PrivateKey>) = [0, 1, 2]
            .iter()
            .map(|_| {
                let kp = SigningKey::generate(&mut OsRng);
                (
                    BasicPrefix::Ed25519(PublicKey::new(kp.verifying_key().to_bytes().to_vec())),
                    PrivateKey::new(kp.to_bytes().to_vec()),
                )
            })
            .unzip();
        let current_threshold = SignatureThreshold::single_weighted(vec![(1, 4), (1, 2), (1, 2)]);

        let next_key_hash = {
            let next_threshold = SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]);
            let next_keys: Vec<BasicPrefix> = [1, 2]
                .iter()
                .map(|_| {
                    let kp = SigningKey::generate(&mut OsRng);
                    BasicPrefix::Ed25519(PublicKey::new(kp.verifying_key().to_bytes().to_vec()))
                })
                .collect();
            nxt_commitment(
                next_threshold,
                &next_keys,
                &HashFunctionCode::Blake3_256.into(),
            )
        };
        let key_config = KeyConfig::new(pub_keys, next_key_hash, Some(current_threshold));

        let msg_to_sign = "message to signed".as_bytes();

        let mut signatures = vec![];
        for i in 0..priv_keys.len() {
            let sig = priv_keys[i].sign_ed(msg_to_sign)?;
            signatures.push(IndexedSignature::new_both_same(
                SelfSigningPrefix::Ed25519Sha512(sig),
                i as u16,
            ));
        }

        // All signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![
                signatures[0].clone(),
                signatures[1].clone(),
                signatures[2].clone(),
            ],
        );
        // assert!(st.is_ok());
        assert!(matches!(st, Ok(true)));

        // Not enough signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![signatures[0].clone(), signatures[2].clone()],
        );
        assert!(matches!(st, Err(SignatureError::NotEnoughSigsError)));

        // Enough signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![signatures[1].clone(), signatures[2].clone()],
        );
        assert!(st.is_ok());

        // The same signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![
                signatures[0].clone(),
                signatures[0].clone(),
                signatures[0].clone(),
            ],
        );
        assert!(matches!(st, Err(SignatureError::DuplicateSignature)));

        Ok(())
    }

    #[test]
    fn test_verify() -> Result<(), Error> {
        use std::convert::TryFrom;

        use crate::{
            event::event_data::EventData,
            event_message::signed_event_message::{Message, Notice},
        };

        // test data taken from keripy
        // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
        let ev = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"0","kt":["1/2","1/2","1/2"],"k":["DCuDiSPCTq-qBBFDHkhf1_kmysrH8KSsFvoaOSgEbx-X","DNUWS4GJHtBpn2Zvgh_ALFuB6E1OJvtphYLvJG8KfI0F","DAVcM7pvoz37lF1HBxFnaZQeGHKC9wVhlytEzKBfzXhV"],"nt":["1/2","1/2","1/2"],"n":["EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy","ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p","EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH"],"bt":"0","b":[],"c":[],"a":[]}-AADAAC3xWTpnv14_khneBqDlrK7JHPUoHNJhWMIXzXbK80RVyEYV7iMsWaAXfepkRsyELBLd25atAtE3iLeDn1I-gUMABDr8iCcrun_otXsarVXpe6jgK2VG20RpgsVvFunUxHsrZRKm6gNjMAoKZkqzDVuY5tKD0XkTmonstex5Wj9dToBACAwNb8Lj-vxJYMi_vIH-ETGG0dVfqIk4ihrQvV1iL1_07eWfu4BwRYCPCZDo0F0Xbkz0DP4xXVfChR-lFd2npUG"#;
        let parsed = parse(ev).unwrap().1;
        let signed_msg = Message::try_from(parsed).unwrap();
        match signed_msg {
            Message::Notice(Notice::Event(ref e)) => {
                if let EventData::Icp(icp) = e.to_owned().event_message.data.get_event_data() {
                    let kc = icp.key_config;
                    let msg = e.event_message.encode()?;
                    assert!(kc.verify(&msg, &e.signatures).is_ok());
                }
            }
            _ => (),
        };

        let ev  = br#"{"v":"KERI10JSON0002a6_","t":"rot","d":"EJ4TG5D0URQ0InD_EIDXDoI9v1y3vIk-0LMJMjeZXryh","i":"EIL2dvwm6lYAsyKKtzxIEFm51gSfwe3IIZSx8kI8ve7_","s":"3","p":"ELKSLVpbV9eH3xk2xBqH3fSgOmWTbUoBuE2JsLl0lu2L","kt":["1/2","1/2","1/2"],"k":["DO1ligy1cGMWDCwIw3HiBLOusTzGOAH88fkUMNsdJkMy","DJoOgGofKsiig4kMjV04ju9UCcIs42XxjOtQQPrNAORe","DEt34Sqbzwgy-VpnzePz5JiTDLEgnUU8RtuDkLn_xJh0"],"nt":[["1/2","1/2","1/2"],["1","1"]],"n":["ENzeDznmpi75oO8APbVzyW75xnmgLDJRo0rCHf4gsDPc","ELnNWeDypTMeaIZzbT8GoJJnbmm8ksJ8ic8b2-9KFZQK","ED2lFBwMbkNQy2vxFWLbbEg2V6OLChhLfTxmvuNGWz91","EHy3gn2wZog-q8V3r6RzduTN48nLEHgSYHaoNaWHrxrl","EHuCmMw5ksFOQxvDSXL9h-_94RMKERjqLj_KFSusuHQg"],"bt":"0","br":[],"ba":[],"a":[]}-AADAACxUM40kMP7aGrPIlwO1d6XAvk6jX22u2EwcB_IgsQSaxJlLbXEz4v2j9cUHQKkY7ek47TfFYir-rG5kyLWJa0MABCQ6AlObGVXjIslKCFZkZiBNvQSDLgUU_2sR4RQxghGCExNWG9jwsSAOFBGX5QcEb6Hqu4ZrdbnyV9GxRkR-jkDACC4Ydi6Jlqw9ROIqNvyHoXNoYcIZzI8iD8_YB1-U9J1xb55jG4z-1Ddyx8mLW6_O53boaFobaitvO13z3u5OswF"#;
        let parsed = parse(ev).unwrap().1;
        let signed_msg = Message::try_from(parsed).unwrap();
        match signed_msg {
            Message::Notice(Notice::Event(ref e)) => {
                if let EventData::Icp(icp) = e.to_owned().event_message.data.get_event_data() {
                    let kc = icp.key_config;
                    let msg = e.event_message.encode()?;
                    assert!(kc.verify(&msg, &e.signatures).is_ok());
                }
            }
            _ => (),
        };

        Ok(())
    }

    #[test]
    pub fn test_finding_matching_previous_indexes() -> Result<(), Error> {
        use crate::signer::setup_signers;

        let signers = setup_signers();
        let hash_function: HashFunction = HashFunctionCode::Blake3_256.into();

        let sample_public_keys: Vec<_> = signers
            .iter()
            .map(|bp| BasicPrefix::Ed25519(bp.public_key()))
            .collect();
        let sample_digests: Vec<_> = sample_public_keys
            .clone()
            .into_iter()
            .map(|pk| hash_function.derive(pk.to_str().as_bytes()))
            .collect();

        let threshold = SignatureThreshold::single_weighted(vec![(1, 4), (1, 2), (1, 4), (1, 2)]);
        let public_keys = sample_public_keys[..5].to_vec();
        let initial_digests: Vec<_> = sample_digests[..5].to_vec();

        // Corresponding previous next keys in the same order as in current keys.
        let indexes = vec![Index::BothSame(0), Index::BothSame(1), Index::BothSame(2)];

        let next_keys_data = NextKeysData::new(threshold.clone(), initial_digests.clone());
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes[..2]),
            vec![0, 1]
        );
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes),
            vec![0, 1, 2]
        );

        // Corresponding previous next keys in other order than in current keys.
        let indexes = vec![
            Index::BothDifferent(0, 2),
            Index::BothDifferent(1, 0),
            Index::BothDifferent(2, 1),
        ];
        let digests = vec![
            initial_digests[1].clone(),
            initial_digests[2].clone(),
            initial_digests[0].clone(),
        ];

        let next_keys_data = NextKeysData::new(threshold.clone(), digests.to_vec());
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes[..2]),
            vec![2, 0]
        );
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes),
            vec![2, 0, 1]
        );

        // Some keys current only
        let indexes = vec![
            Index::CurrentOnly(0),
            Index::BothDifferent(1, 2),
            Index::BothDifferent(2, 1),
        ];
        let digests = vec![
            initial_digests[0].clone(),
            initial_digests[2].clone(),
            initial_digests[1].clone(),
        ];

        let next_keys_data = NextKeysData::new(threshold.clone(), digests.to_vec());
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes[..2]),
            vec![2]
        );
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes),
            vec![2, 1]
        );

        // Bad digest
        let indexes = vec![
            Index::CurrentOnly(0),
            Index::BothDifferent(1, 2),
            Index::BothDifferent(2, 1),
        ];
        let digests = vec![
            initial_digests[0].clone(),
            initial_digests[2].clone(),
            hash_function.derive("Bad digest".as_bytes()),
        ];

        let next_keys_data = NextKeysData::new(threshold.clone(), digests.to_vec());
        assert_eq!(
            next_keys_data.matching_previous_indexes(&public_keys, &indexes),
            vec![1]
        );

        Ok(())
    }
}
