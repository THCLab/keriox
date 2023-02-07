use cesrox::primitives::CesrPrimitive;
use sai::{derivation::SelfAddressing, SelfAddressingPrefix};
use serde::{Deserialize, Serialize};

use super::threshold::SignatureThreshold;
use crate::{
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix},
};

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NextKeysData {
    #[serde(rename = "nt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "n")]
    pub next_key_hashes: Vec<SelfAddressingPrefix>,
}

impl NextKeysData {
    pub fn verify_next(&self, next: &KeyConfig) -> Result<bool, Error> {
        let mut indexes = vec![];
        for key in &next.public_keys {
            let sigs_indexes = self
                .next_key_hashes
                .iter()
                .position(|dig| dig.verify_binding(key.to_str().as_bytes()))
                .ok_or_else(|| {
                    Error::SemanticError("No such public key in next keys hashes".into())
                })?;
            indexes.push(sigs_indexes);
        }
        // check previous next threshold
        self.threshold
            .enough_signatures(&indexes)?
            .then_some(true)
            .ok_or(Error::NotEnoughSigsError)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
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
    pub fn verify(&self, message: &[u8], sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        // there are no duplicates
        if !(sigs
            .iter()
            .fold(vec![0u64; self.public_keys.len()], |mut acc, sig| {
                acc[sig.index as usize] += 1;
                acc
            })
            .iter()
            .all(|n| *n <= 1))
        {
            Err(Error::DuplicateSignature)
        } else if
        // check if there are not too many
        sigs.len() > self.public_keys.len() {
            Err(Error::TooManySignatures)

        // ensure there's enough sigs
        } else if self.threshold.enough_signatures(
            &sigs
                .iter()
                .map(|sig| sig.index as usize)
                .collect::<Vec<_>>(),
        )? {
            Ok(sigs
                .iter()
                .fold(Ok(true), |acc: Result<bool, Error>, sig| {
                    Ok(acc?
                        && self
                            .public_keys
                            .get(sig.index as usize)
                            .ok_or_else(|| {
                                Error::SemanticError("Key index not present in set".into())
                            })
                            .and_then(|key: &BasicPrefix| {
                                Ok(key.verify(message, &sig.signature)?)
                            })?)
                })?)
        } else {
            Err(Error::NotEnoughSigsError)
        }
    }

    /// Verify Next
    ///
    /// Verifies that the given next KeyConfig matches that which is committed
    /// to in next_keys_data of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> Result<bool, Error> {
        self.next_keys_data.verify_next(next)
    }

    /// Serialize For Next
    ///
    /// Serializes the KeyConfig for creation or verification of a threshold
    /// key digest commitment
    pub fn commit(&self, derivation: &SelfAddressing) -> NextKeysData {
        nxt_commitment(self.threshold.clone(), &self.public_keys, derivation)
    }
}

/// Serialize For Commitment
///
/// Creates NextKeysData from given threshold and public keys set.
pub fn nxt_commitment(
    threshold: SignatureThreshold,
    keys: &[BasicPrefix],
    derivation: &SelfAddressing,
) -> NextKeysData {
    let next_key_hashes = keys
        .iter()
        .map(|bp| derivation.derive(bp.to_str().as_bytes()))
        .collect();
    NextKeysData {
        threshold,
        next_key_hashes,
    }
}

#[cfg(test)]
mod test {
    use cesrox::parse;
    use sai::{derivation::SelfAddressing, SelfAddressingPrefix};

    use crate::{
        error::Error,
        event::sections::{
            key_config::{nxt_commitment, NextKeysData},
            threshold::SignatureThreshold,
            KeyConfig,
        },
        prefix::{AttachedSignaturePrefix, BasicPrefix},
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
        let nxt = nxt_commitment(sith, &next_keys, &SelfAddressing::Blake3_256);

        let threshold = SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
        let next_key_hashes: Vec<SelfAddressingPrefix> = [
            "EFQZkN8MMEtZzaS-Tq1EEbH886vsf5SzwicSn_ywbzTy",
            "ENOQnUj8GNr1ICJ1P4qmC3-aHTrpZqKVpZhvHCBVWE1p",
            "EDFH1MfEJWlI9PpMbgBi_RGP7L4UivrLfozFucuEaWVH",
        ]
        .iter()
        .map(|sai| sai.parse().unwrap())
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
        use ed25519_dalek::Keypair;
        use rand::rngs::OsRng;

        use crate::{
            keys::{PrivateKey, PublicKey},
            prefix::SelfSigningPrefix,
        };

        let (pub_keys, priv_keys): (Vec<BasicPrefix>, Vec<PrivateKey>) = [0, 1, 2]
            .iter()
            .map(|_| {
                let kp = Keypair::generate(&mut OsRng);
                (
                    BasicPrefix::Ed25519(PublicKey::new(kp.public.to_bytes().to_vec())),
                    PrivateKey::new(kp.secret.to_bytes().to_vec()),
                )
            })
            .unzip();
        let current_threshold = SignatureThreshold::single_weighted(vec![(1, 4), (1, 2), (1, 2)]);

        let next_key_hash = {
            let next_threshold = SignatureThreshold::single_weighted(vec![(1, 2), (1, 2)]);
            let next_keys: Vec<BasicPrefix> = [1, 2]
                .iter()
                .map(|_| {
                    let kp = Keypair::generate(&mut OsRng);
                    BasicPrefix::Ed25519(PublicKey::new(kp.public.to_bytes().to_vec()))
                })
                .collect();
            nxt_commitment(next_threshold, &next_keys, &SelfAddressing::Blake3_256)
        };
        let key_config = KeyConfig::new(pub_keys, next_key_hash, Some(current_threshold));

        let msg_to_sign = "message to signed".as_bytes();

        let mut signatures = vec![];
        for i in 0..priv_keys.len() {
            let sig = priv_keys[i].sign_ed(msg_to_sign)?;
            signatures.push(AttachedSignaturePrefix::new(
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
        assert!(matches!(st, Ok(true)));

        // Not enough signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![signatures[0].clone(), signatures[2].clone()],
        );
        assert!(matches!(st, Err(Error::NotEnoughSigsError)));

        // Enough signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![signatures[1].clone(), signatures[2].clone()],
        );
        assert!(matches!(st, Ok(true)));

        // The same signatures.
        let st = key_config.verify(
            msg_to_sign,
            &vec![
                signatures[0].clone(),
                signatures[0].clone(),
                signatures[0].clone(),
            ],
        );
        assert!(matches!(st, Err(Error::DuplicateSignature)));

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
                    assert!(kc.verify(&msg, &e.signatures)?);
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
                    assert!(kc.verify(&msg, &e.signatures)?);
                }
            }
            _ => (),
        };

        Ok(())
    }
}
