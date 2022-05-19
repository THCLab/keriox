use serde::{Deserialize, Serialize};

use crate::{
    derivation::self_addressing::SelfAddressing,
    error::Error,
    prefix::{AttachedSignaturePrefix, BasicPrefix, Prefix, SelfAddressingPrefix},
};

use super::threshold::SignatureThreshold;

#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq)]
pub struct KeyConfig {
    #[serde(rename = "kt")]
    pub threshold: SignatureThreshold,

    #[serde(rename = "k")]
    pub public_keys: Vec<BasicPrefix>,

    #[serde(rename = "n", with = "empty_string_as_none")]
    pub threshold_key_digest: Option<SelfAddressingPrefix>,
}

impl KeyConfig {
    pub fn new(
        public_keys: Vec<BasicPrefix>,
        threshold_key_digest: Option<SelfAddressingPrefix>,
        threshold: Option<SignatureThreshold>,
    ) -> Self {
        Self {
            threshold: threshold.map_or_else(
                || SignatureThreshold::Simple(public_keys.len() as u64 / 2 + 1),
                |t| t,
            ),
            public_keys,
            threshold_key_digest,
        }
    }

    /// Verify
    ///
    /// Verifies the given sigs against the given message using the KeyConfigs
    /// Public Keys, according to the indexes in the sigs.
    pub fn verify(&self, message: &[u8], sigs: &[AttachedSignaturePrefix]) -> Result<bool, Error> {
        // ensure there's enough sigs
        if !self.threshold.enough_signatures(sigs)? {
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
    /// to in the threshold_key_digest of this KeyConfig
    pub fn verify_next(&self, next: &KeyConfig) -> bool {
        match &self.threshold_key_digest {
            Some(n) => n == &next.commit(&n.derivation),
            None => false,
        }
    }

    /// Serialize For Next
    ///
    /// Serializes the KeyConfig for creation or verification of a threshold
    /// key digest commitment
    pub fn commit(&self, derivation: &SelfAddressing) -> SelfAddressingPrefix {
        nxt_commitment(&self.threshold, &self.public_keys, derivation)
    }
}

/// Serialize For Commitment
///
/// Serializes a threshold and key set into the form
/// required for threshold key digest creation
pub fn nxt_commitment(
    threshold: &SignatureThreshold,
    keys: &[BasicPrefix],
    derivation: &SelfAddressing,
) -> SelfAddressingPrefix {
    let extracted_threshold = match threshold {
        SignatureThreshold::Simple(n) => format!("{:x}", n),
        SignatureThreshold::Weighted(thresh) => thresh.extract_threshold(),
    };
    keys.iter().fold(
        derivation.derive(extracted_threshold.as_bytes()),
        |acc, pk| {
            SelfAddressingPrefix::new(
                derivation.to_owned(),
                acc.derivative()
                    .iter()
                    .zip(derivation.derive(pk.to_str().as_bytes()).derivative())
                    .map(|(acc_byte, pk_byte)| acc_byte ^ pk_byte)
                    .collect(),
            )
        },
    )
}

mod empty_string_as_none {
    use serde::{de::IntoDeserializer, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'d, D, T>(de: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'d>,
        T: Deserialize<'d>,
    {
        let opt = Option::<String>::deserialize(de)?;
        let opt = opt.as_deref();
        match opt {
            None | Some("") => Ok(None),
            Some(s) => T::deserialize(s.into_deserializer()).map(Some),
        }
    }

    pub fn serialize<S, T>(t: &Option<T>, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: ToString,
    {
        s.serialize_str(&match &t {
            Some(v) => v.to_string(),
            None => "".into(),
        })
    }
}

#[test]
fn test_next_commitment() {
    // test data taken from kid0003
    let keys: Vec<BasicPrefix> = [
        "BrHLayDN-mXKv62DAjFLX1_Y5yEUe0vA9YPe_ihiKYHE",
        "BujP_71bmWFVcvFmkE9uS8BTZ54GIstZ20nj_UloF8Rk",
        "B8T4xkb8En6o0Uo5ZImco1_08gT5zcYnXzizUPVNzicw",
    ]
    .iter()
    .map(|k| k.parse().unwrap())
    .collect();

    let sith = SignatureThreshold::Simple(2);
    let nxt = nxt_commitment(&sith, &keys, &SelfAddressing::Blake3_256);

    assert_eq!(
        &nxt.to_str(),
        "ED8YvDrXvGuaIVZ69XsBVA5YN2pNTfQOFwgeloVHeWKs"
    );

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
    let nxt = nxt_commitment(&sith, &next_keys, &SelfAddressing::Blake3_256);
    assert_eq!(nxt.to_str(), "EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI");
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
        nxt_commitment(&next_threshold, &next_keys, &SelfAddressing::Blake3_256)
    };
    let key_config = KeyConfig::new(pub_keys, Some(next_key_hash), Some(current_threshold));

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
    let ev = br#"{"v":"KERI10JSON00018e_","t":"icp","d":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-DdTfkEk8s","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-DdTfkEk8s","s":"0","kt":["1/2","1/2","1/2"],"k":["DK4OJI8JOr6oEEUMeSF_X-SbKysfwpKwW-ho5KARvH5c","D1RZLgYke0GmfZm-CH8AsW4HoTU4m-2mFgu8kbwp8jQU","DBVwzum-jPfuUXUcHEWdplB4YcoL3BWGXK0TMoF_NeFU"],"n":"EhJGhyJQTpSlZ9oWfQT-lHNl1woMazLC42O89fRHocTI","bt":"0","b":[],"c":[],"a":[]}-AADAAo74mzRNAT5WEVRYaUWs4apfEY9oblVL2MtNSORwsEVFNoyH8Vh_w_WC9TGfH-_zqN8dISIy102JtmBwllvHnBAABYQAmtsf2yhqi0zvF--TVWp7kfzVRy3BQkTdYmJrfOZFnvp0kbXlG-PCXPO7OXbKM0ZLJ1Ga_qVJ_y-ERIMacCwACInxprKSzFp2-LNPn7eVAAc8z0XO0KbUE26vv_PXt5IMwyx6S5A1nCC4DQrv6bYHmmXP0YQpkOIm-tRHrPCOuDg'"#;
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

    let ev = br#"{"v":"KERI10JSON000231_","t":"rot","d":"EDK-dx1__PH_ZJXeZBfxVnodjUsaczSocKCNluEV6Cec","i":"EZgXYINAQWXFpxAmWI9AwOwjVOYXzjyEE_-DdTfkEk8s","s":"4","p":"Ebhb0Fnink_-r0JfJQIVr15G0Ew8upPjo94-cT3SzdlU","kt":[["1/2","1/2","1/2"],["1/1","1/1"]],"k":["DToUWoemnetqJoLFIqDI7lxIJEfF0W7xG5ZlqAseVUQc","Drz-IZjko61q-sPMDIW6n-0NGFubbXiZhzWZrO_BZ0Wc","DiGwL3hjQqiUgQlFPeA6kRR1EBXX0vSLm9b6QhPS8IkQ","Dxj5pcStgZ6CbQ2YktNaj8KLE_g9YAOZF6AL9fyLcWQw","DE5zr5eH8EUVQXyAaxWfQUWkGCId-QDCvvxMT77ibj2Q"],"n":"E3in3Z14va0kk4Wqd3vcCAojKNtQq7ZTrQaavR8x0yu4","bt":"0","br":[],"ba":[],"a":[]}-AAFAAt2EjEPyJOMqtUdrp2EaRenlwriXviQ0hJ4Wx0agCok1sU3QMFS5hRdwX_NEFca9OnKGVjOag6K_F4yOs1BiuDQABN30bxBTVoemwfv6bPMqi9aIBKAuqm5IjcXFpS6vdnSdcQiz5VWb5DzpjhBztZyTiBbmxihl4tGyJ8xMTlIcmAwACq5YQaTJ45Smm2UwhyX5YLVkvxeJxt9oewmGAhOxyp-_tu0KAe2mehFHa6s9BlcqE-401mQh5EcniFbdHx3eAAQADR8Mtsn-7UKC-LjWq45-tKJfV8QVTaAXGiQsXye6DC7cf5iKQeUw7NXIcuxb-CXLL3AIMg3ZfhYy44-wW6pq6BgAEPtQg63EnWDfhwQjqgIlAHGupkeE_2hZhEp2Lcx0m5x4w0S6XqR9_Lx86RMnrzc3G9W3CJ_V5iEJhNQAqdTFqCw"#;
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
