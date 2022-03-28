use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};

use super::threshold::SignatureThreshold;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct NextKeysData {
    #[serde(rename = "nt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "n")]
    pub next_key_hashes: Vec<SelfAddressingPrefix>,
}

impl NextKeysData {
    pub fn verify_next(&self, next: &KeyConfig) -> bool {
        // let check_keys = self
        //     .next_key_hashes
        //     .iter()
        //     .zip(next.public_keys.iter())
        //     .all(|(hash, key)| hash.verify_binding(key.to_str().as_bytes()));
        let mut indexes = vec![];
        for key in &next.public_keys {
            let sigs_indexes = self.next_key_hashes
                .iter()
                .enumerate()
                .find(|(i, dig)| 
                    dig.verify_binding(key.to_str().as_bytes())
                ).ok_or(Error::SemanticError("No such public key in next keys hashes".into())).unwrap();
                indexes.push(sigs_indexes.0);
            
        };
        // check previous next threshold
        self.threshold.enough_signatures(&indexes).unwrap()
        // TODO check current threshold?
        // self.threshold == next.threshold && check_keys
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
        // ensure there's enough sigs
        if !self.threshold.enough_signatures(&sigs.iter().map(|sig| sig.index as usize).collect::<Vec<_>>())? {
            Err(Error::NotEnoughSigsError)
        } else if
        // and that there are not too many
        sigs.len() <= self.public_keys.len()
            // and that there are no duplicates
            && sigs
                .iter()
                .fold(vec![0u64; self.public_keys.len()], |mut acc, sig| {
                    acc[sig.index as usize] += 1;
                    acc
                })
                .iter()
                .all(|n| *n <= 1)
        {
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
                            .and_then(|key: &BasicPrefix| key.verify(message, &sig.signature))?)
                })?)
        } else {
            Err(Error::SemanticError("Invalid signatures set".into()))
        }
    }

    /// Verify Next
    ///
    /// Verifies that the given next KeyConfig matches that which is committed
    /// to in next_keys_data of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> bool {
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

#[test]
fn test_next_commitment() {
    // test data taken from keripy
    // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
    // Set weighted threshold to [1/2, 1/2, 1/2]
    let sith = SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
    let next_keys: Vec<BasicPrefix> = [
        "DeonYM2bKnAwp6VZcuCXdX72kNFw56czlZ_Tc7XHHVGI",
        "DQghKIy-2do9OkweSgazh3Ql1vCOt5bnc5QF8x50tRoU",
        "DNAUn-5dxm6b8Njo01O0jlStMRCjo9FYQA2mfqFW1_JA",
    ]
    .iter()
    .map(|x| x.parse().unwrap())
    .collect();
    let nxt = nxt_commitment(sith, &next_keys, &SelfAddressing::Blake3_256);

    let threshold = SignatureThreshold::multi_weighted(vec![vec![(1, 2), (1, 2), (1, 2)]]);
    let next_key_hashes: Vec<SelfAddressingPrefix> = [
        "E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc",
        "Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4",
        "EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0",
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
    use crate::derivation::{basic::Basic, self_signing::SelfSigning};
    use crate::keys::{PrivateKey, PublicKey};
    use ed25519_dalek::Keypair;
    use rand::rngs::OsRng;

    let (pub_keys, priv_keys): (Vec<BasicPrefix>, Vec<PrivateKey>) = [0, 1, 2]
        .iter()
        .map(|_| {
            let kp = Keypair::generate(&mut OsRng);
            (
                Basic::Ed25519.derive(PublicKey::new(kp.public.to_bytes().to_vec())),
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
                Basic::Ed25519.derive(PublicKey::new(kp.public.to_bytes().to_vec()))
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
            SelfSigning::Ed25519Sha512,
            sig,
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
    assert!(matches!(st, Err(Error::NotEnoughSigsError)));

    Ok(())
}

#[test]
fn test_verify() -> Result<(), Error> {
    use crate::event::event_data::EventData;
    use crate::event_message::signed_event_message::Message;
    use crate::event_parsing::message::signed_message;
    use std::convert::TryFrom;

    // test data taken from keripy
    // (keripy/tests/core/test_weighted_threshold.py::test_weighted)
    let ev = br#"{"v":"KERI10JSON000207_","t":"icp","d":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"nt":["1/2","1/2","1/2"],"n":["E9tzF91cgL0Xu4UkCqlCbDxXK-HnxmmTIwTi_ySgjGLc","Ez53UFJ6euROznsDhnPr4auhJGgzeM5ln5i-Tlp8V3L4","EPF1apCK5AUL7k4AlFG4pSEgQX0h-kosQ_tfUtPJ_Ti0"],"bt":"0","b":[],"c":[],"a":[]}-AADAAjCyfd63fzueQfpOHGgSl4YvEXsc3IYpdlvXDKfpbicV8pGj2v-TWBDyFqkzIdB7hMhG1iR3IeS7vy3a3catGDgABhGYRTHmUMPIj2LV5iJLe6BtaO_ohLAVyP9mW0U4DdYT0Uiqh293sGFJ6e47uCkOqoLu9B6dF7wl-llurp3o5BAACJz5biC59pvOpb3aUadlNr_BZb-laG1zgX7FtO5Q0M_HPJObtlhVtUghTBythEb8FpoLze8WnEWUayJnpLsYjAA"#;
    let parsed = signed_message(ev).unwrap().1;
    let signed_msg = Message::try_from(parsed).unwrap();
    match signed_msg {
        Message::Event(ref e) => {
            if let EventData::Icp(icp) = e.to_owned().event_message.event.get_event_data() {
                let kc = icp.key_config;
                let msg = e.event_message.serialize()?;
                assert!(kc.verify(&msg, &e.signatures)?);
            }
        }
        _ => (),
    };

    let ev  = br#"{"v":"KERI10JSON0002aa_","t":"rot","d":"EpaAOKbdwjjI7CAikCJDCr6rzmN14frB_cwif4MBnsTk","i":"EOsgPPbBijCbpu3R9N-TMdURgcoFqrjUf3rQiIaJ5L7M","s":"3","p":"EXlVGTrAuFlYjj1o1389Vfr1SecFYKJq4J9HkjlPyVqY","kt":["1/2","1/2","1/2"],"k":["D7WWKDLVwYxYMLAjDceIEs66xPMY4Afzx-RQw2x0mQzI","Dmg6Aah8qyKKDiQyNXTiO71QJwizjZfGM61BA-s0A5F4","DS3fhKpvPCDL5WmfN4_PkmJMMsSCdRTxG24OQuf_EmHQ"],"nt":[["1/2","1/2","1/2"],["1/1","1/1"]],"n":["Ehru1umWyy696CK10v2ROEOv8csx-S4KtYZHF4RbV3gc","EdsEn6HJLVLrhle11lqgImN0s7BQV03CfqxYpxs0qcrg","ED2DjOJWZyGUxGr_CFKA45dsmV72LvIvJWcB1xpuVGvM","EMwx5v3RMAjQ0GHdg5VR7XG2-2Cg4Kgslmn2lMCJ-oYs","EHN09tKWiJl83SPiBB_KDN1TKDutErXADGnl3TSx7ZLk"],"bt":"0","br":[],"ba":[],"a":[]}-AADAAHjkEbbFN_QkGinYurCnQphjMOgfDdfuIyVNgn9krq-vYuJSlwhilVWquumLiJL7oCOJmF6aFDWcKKScNKiPHDgABQsjiEna5VZ7vE5ayRPswdjW2z19xRUyg4pktVGGw3yv9OvP6XUDRbvxUs36hndwWE6y894bVbx5XUWWe5jDnCgACMMQCX8qjNcbHik2ukkv9mV45p3wgcxhuk_LMpXwt8KUT0eRwBHtnYuhFvXHYIDvaLTao4RxBg8AJhx8L-OdsDg"#;
    let parsed = signed_message(ev).unwrap().1;
    let signed_msg = Message::try_from(parsed).unwrap();
    match signed_msg {
        Message::Event(ref e) => {
            if let EventData::Icp(icp) = e.to_owned().event_message.event.get_event_data() {
                let kc = icp.key_config;
                let msg = e.event_message.serialize()?;
                assert!(kc.verify(&msg, &e.signatures)?);
            }
        }
        _ => (),
    };

    Ok(())
}
